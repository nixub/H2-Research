/*
 * Copyright 2004-2021 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (https://h2database.com/html/license.html).
 * Initial Developer: H2 Group
 */
package org.h2.command.dml;

import org.h2.api.ErrorCode;
import org.h2.api.Trigger;
import org.h2.command.Command;
import org.h2.command.CommandInterface;
import org.h2.command.query.Query;
import org.h2.engine.DbObject;
import org.h2.engine.Right;
import org.h2.engine.SessionLocal;
import org.h2.expression.*;
import org.h2.expression.condition.Comparison;
import org.h2.expression.condition.ConditionAndOr;
import org.h2.index.Index;
import org.h2.message.DbException;
import org.h2.mvstore.db.MVPrimaryIndex;
import org.h2.result.ResultInterface;
import org.h2.result.ResultTarget;
import org.h2.result.Row;
import org.h2.table.Column;
import org.h2.table.DataChangeDeltaTable;
import org.h2.table.DataChangeDeltaTable.ResultOption;
import org.h2.table.Table;
import org.h2.util.HasSQL;
import org.h2.value.Value;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map.Entry;

/**
 * This class represents the statement
 * INSERT
 */
public final class Insert extends CommandWithValues implements ResultTarget {

    private Table table;
    private Column[] columns;
    private Query query;
    private long rowNumber;
    private boolean insertFromSelect;

    private Boolean overridingSystem;

    /**
     * For MySQL-style INSERT ... ON DUPLICATE KEY UPDATE ....
     */
    private HashMap<Column, Expression> duplicateKeyAssignmentMap;

    private Value[] onDuplicateKeyRow;

    /**
     * For MySQL-style INSERT IGNORE and PostgreSQL-style ON CONFLICT DO
     * NOTHING.
     */
    private boolean ignore;

    private ResultTarget deltaChangeCollector;

    private ResultOption deltaChangeCollectionMode;

    public Insert(SessionLocal session) {
        super(session);
    }

    @Override
    public void setCommand(Command command) {
        super.setCommand(command);
        if (query != null) {
            query.setCommand(command);
        }
    }

    @Override
    public Table getTable() {
        return table;
    }

    public void setTable(Table table) {
        this.table = table;
    }

    public void setColumns(Column[] columns) {
        this.columns = columns;
    }

    /**
     * Sets MySQL-style INSERT IGNORE mode or PostgreSQL-style ON CONFLICT
     * DO NOTHING.
     *
     * @param ignore ignore duplicates
     */
    public void setIgnore(boolean ignore) {
        this.ignore = ignore;
    }

    public void setQuery(Query query) {
        this.query = query;
    }

    public void setOverridingSystem(Boolean overridingSystem) {
        this.overridingSystem = overridingSystem;
    }

    /**
     * Keep a collection of the columns to pass to update if a duplicate key
     * happens, for MySQL-style INSERT ... ON DUPLICATE KEY UPDATE ....
     *
     * @param column the column
     * @param expression the expression
     */
    public void addAssignmentForDuplicate(Column column, Expression expression) {
        if (duplicateKeyAssignmentMap == null) {
            duplicateKeyAssignmentMap = new HashMap<>();
        }
        if (duplicateKeyAssignmentMap.putIfAbsent(column, expression) != null) {
            throw DbException.get(ErrorCode.DUPLICATE_COLUMN_NAME_1, column.getName());
        }
    }

    //插入数据也走了这个方法
    @Override
    public long update(ResultTarget deltaChangeCollector, ResultOption deltaChangeCollectionMode) {
        this.deltaChangeCollector = deltaChangeCollector;
        this.deltaChangeCollectionMode = deltaChangeCollectionMode;
        try {

            return insertRows();
        } finally {
            this.deltaChangeCollector = null;
            this.deltaChangeCollectionMode = null;
        }
    }
    //当插入一个数据时，所执行的逻辑
    private long insertRows() {
        session.getUser().checkTableRight(table, Right.INSERT);
        setCurrentRowNumber(0);
        table.fire(session, Trigger.INSERT, true);
        rowNumber = 0;
        int listSize = valuesExpressionList.size();
        if (listSize > 0) {
            int columnLen = columns.length;
            for (int x = 0; x < listSize; x++) {
                //根据模板 获取行对象，实现略微复杂 ，用到工厂模式。
                Row newRow = table.getTemplateRow(); //newRow的长度是全表字段的个数，会>=columns的长度
                // expr  就是传来的数据 数组  ---表达式是查询中的操作、值或函数。
                Expression[] expr = valuesExpressionList.get(x);
                setCurrentRowNumber(x + 1);
                //把值循环放到行对象中
                for (int i = 0; i < columnLen; i++) {
                    Column c = columns[i];
                    int index = c.getColumnId(); //从0开始
                    Expression e = expr[i];
                    if (e != ValueExpression.DEFAULT) {
                        try {
                            newRow.setValue(index, e.getValue(session));
                        } catch (DbException ex) {
                            throw setRow(ex, x, getSimpleSQL(expr));
                        }
                    }
                }
                rowNumber++;
                //为 INSERT 操作准备指定的行。  如何理解？
                //      *
                //      * 评估身份、默认值和生成值，所有值都是
                //      * 转换为目标数据类型并经过验证。 身份基础值
                //      * 列在兼容模式需要时更新。
                table.convertInsertRow(session, newRow, overridingSystem);
                if (deltaChangeCollectionMode == ResultOption.NEW) {
                    deltaChangeCollector.addRow(newRow.getValueList().clone());
                }
                if (!table.fireBeforeRow(session, null, newRow)) { //INSTEAD OF触发器会返回true
                    //直到事务commit或rollback时才解琐，见org.h2.engine.Session.unlockAll()
                    table.lock(session, true, false);
                    try {
                        table.addRow(session, newRow);
                    } catch (DbException de) {
                        if (handleOnDuplicate(de, null)) {
                            // MySQL returns 2 for updated row
                            // TODO: detect no-op change
                            rowNumber++;
                        } else {
                            // INSERT IGNORE case
                            rowNumber--;
                        }
                        continue;
                    }
                    DataChangeDeltaTable.collectInsertedFinalRow(session, table, deltaChangeCollector,
                            deltaChangeCollectionMode, newRow);
                    table.fireAfterRow(session, null, newRow, false);
                } else {
                    DataChangeDeltaTable.collectInsertedFinalRow(session, table, deltaChangeCollector,
                            deltaChangeCollectionMode, newRow);
                }
            }
        } else {
            table.lock(session, true, false);
            //这种方式主要是避免循环两次，因为query内部己循环一次了，得到记录后像else中的非insertFromSelect一样，还要循环一次
            if (insertFromSelect) {
                query.query(0, this); //每遍历一行会回调下面的addRow方法
            } else {
                ResultInterface rows = query.query(0);
                while (rows.next()) {
                    Value[] r = rows.currentRow();
                    try {
                        addRow(r);
                    } catch (DbException de) {
                        if (handleOnDuplicate(de, r)) {
                            // MySQL returns 2 for updated row
                            // TODO: detect no-op change
                            rowNumber++;
                        } else {
                            // INSERT IGNORE case
                            rowNumber--;
                        }
                    }
                }
                rows.close();
            }
        }
        table.fire(session, Trigger.INSERT, false);
        return rowNumber;
    }

    @Override
    public void addRow(Value... values) {
        Row newRow = table.getTemplateRow();
        setCurrentRowNumber(++rowNumber);
        for (int j = 0, len = columns.length; j < len; j++) {
            newRow.setValue(columns[j].getColumnId(), values[j]);
        }
        table.convertInsertRow(session, newRow, overridingSystem);
        if (deltaChangeCollectionMode == ResultOption.NEW) {
            deltaChangeCollector.addRow(newRow.getValueList().clone());
        }
        if (!table.fireBeforeRow(session, null, newRow)) {
            table.addRow(session, newRow);
            DataChangeDeltaTable.collectInsertedFinalRow(session, table, deltaChangeCollector,
                    deltaChangeCollectionMode, newRow);
            table.fireAfterRow(session, null, newRow, false);
        } else {
            DataChangeDeltaTable.collectInsertedFinalRow(session, table, deltaChangeCollector,
                    deltaChangeCollectionMode, newRow);
        }
    }

    @Override
    public long getRowCount() {
        // This method is not used in this class
        return rowNumber;
    }

    @Override
    public void limitsWereApplied() {
        // Nothing to do
    }

    @Override
    public String getPlanSQL(int sqlFlags) {
        StringBuilder builder = new StringBuilder("INSERT INTO ");
        table.getSQL(builder, sqlFlags).append('(');
        Column.writeColumns(builder, columns, sqlFlags);
        builder.append(")\n");
        if (insertFromSelect) {
            builder.append("DIRECT ");
        }
        if (!valuesExpressionList.isEmpty()) {
            builder.append("VALUES ");
            int row = 0;
            if (valuesExpressionList.size() > 1) {
                builder.append('\n');
            }
            for (Expression[] expr : valuesExpressionList) {
                if (row++ > 0) {
                    builder.append(",\n");
                }
                Expression.writeExpressions(builder.append('('), expr, sqlFlags).append(')');
            }
        } else {
            builder.append(query.getPlanSQL(sqlFlags));
        }
        return builder.toString();
    }

    @Override
    public void prepare() {
        if (columns == null) {
        	//如INSERT INTO InsertTest DEFAULT VALUES
            if (!valuesExpressionList.isEmpty() && valuesExpressionList.get(0).length == 0) {
                // special case where table is used as a sequence
                columns = new Column[0];
            } else { //如INSERT INTO InsertTest(SELECT * FROM tmpSelectTest)
                columns = table.getColumns();
            }
        }
        if (!valuesExpressionList.isEmpty()) {
            for (Expression[] expr : valuesExpressionList) {
                if (expr.length != columns.length) {
                    throw DbException.get(ErrorCode.COLUMN_COUNT_DOES_NOT_MATCH);
                }
                for (int i = 0, len = expr.length; i < len; i++) {
                    Expression e = expr[i];
                    if (e != null) {
                        e = e.optimize(session);
                        if (e instanceof Parameter) {
                            Parameter p = (Parameter) e;
                            p.setColumn(columns[i]);
                        }
                        expr[i] = e;
                    }
                }
            }
        } else {
            query.prepare();
            if (query.getColumnCount() != columns.length) {
                throw DbException.get(ErrorCode.COLUMN_COUNT_DOES_NOT_MATCH);
            }
        }
    }

    @Override
    public int getType() {
        return CommandInterface.INSERT;
    }

    @Override
    public String getStatementName() {
        return "INSERT";
    }

    public void setInsertFromSelect(boolean value) {
        this.insertFromSelect = value;
    }

    @Override
    public boolean isCacheable() {
        return duplicateKeyAssignmentMap == null;
    }

    /**
     * @param de duplicate key exception
     * @param currentRow current row values (optional)
     * @return {@code true} if row was updated, {@code false} if row was ignored
     */
    private boolean handleOnDuplicate(DbException de, Value[] currentRow) {
        if (de.getErrorCode() != ErrorCode.DUPLICATE_KEY_1) {
            throw de;
        }
        if (duplicateKeyAssignmentMap == null) {
            if (ignore) {
                return false;
            }
            throw de;
        }

        int columnCount = columns.length;
        Expression[] row = (currentRow == null) ? valuesExpressionList.get((int) getCurrentRowNumber() - 1)
                : new Expression[columnCount];
        onDuplicateKeyRow = new Value[table.getColumns().length];
        for (int i = 0; i < columnCount; i++) {
            Value value;
            if (currentRow != null) {
                value = currentRow[i];
                row[i] = ValueExpression.get(value);
            } else {
                value = row[i].getValue(session);
            }
            onDuplicateKeyRow[columns[i].getColumnId()] = value;
        }

        StringBuilder builder = new StringBuilder("UPDATE ");
        table.getSQL(builder, HasSQL.DEFAULT_SQL_FLAGS).append(" SET ");
        boolean f = false;
        for (Entry<Column, Expression> entry : duplicateKeyAssignmentMap.entrySet()) {
            if (f) {
                builder.append(", ");
            }
            f = true;
            entry.getKey().getSQL(builder, HasSQL.DEFAULT_SQL_FLAGS).append('=');
            entry.getValue().getUnenclosedSQL(builder, HasSQL.DEFAULT_SQL_FLAGS);
        }
        builder.append(" WHERE ");
        Index foundIndex = (Index) de.getSource();
        if (foundIndex == null) {
            throw DbException.getUnsupportedException(
                    "Unable to apply ON DUPLICATE KEY UPDATE, no index found!");
        }
        prepareUpdateCondition(foundIndex, row).getUnenclosedSQL(builder, HasSQL.DEFAULT_SQL_FLAGS);
        String sql = builder.toString();
        Update command = (Update) session.prepare(sql);
        command.setOnDuplicateKeyInsert(this);
        for (Parameter param : command.getParameters()) {
            Parameter insertParam = parameters.get(param.getIndex());
            param.setValue(insertParam.getValue(session));
        }
        boolean result = command.update() > 0;
        onDuplicateKeyRow = null;
        return result;
    }

    private Expression prepareUpdateCondition(Index foundIndex, Expression[] row) {
        // MVPrimaryIndex is playing fast and loose with it's implementation of
        // the Index interface.
        // It returns all of the columns in the table when we call
        // getIndexColumns() or getColumns().
        // Don't have time right now to fix that, so just special-case it.
        // PageDataIndex has the same problem.
        final Column[] indexedColumns;
        if (foundIndex instanceof MVPrimaryIndex) {
            MVPrimaryIndex foundMV = (MVPrimaryIndex) foundIndex;
            indexedColumns = new Column[] { foundMV.getIndexColumns()[foundMV
                    .getMainIndexColumn()].column };
        } else {
            indexedColumns = foundIndex.getColumns();
        }

        Expression condition = null;
        for (Column column : indexedColumns) {
            ExpressionColumn expr = new ExpressionColumn(session.getDatabase(),
                    table.getSchema().getName(), table.getName(), column.getName());
            for (int i = 0; i < columns.length; i++) {
                if (expr.getColumnName(session, i).equals(columns[i].getName())) {
                    if (condition == null) {
                        condition = new Comparison(Comparison.EQUAL, expr, row[i], false);
                    } else {
                        condition = new ConditionAndOr(ConditionAndOr.AND, condition,
                                new Comparison(Comparison.EQUAL, expr, row[i], false));
                    }
                    break;
                }
            }
        }
        return condition;
    }

    /**
     * Get the value to use for the specified column in case of a duplicate key.
     *
     * @param columnIndex the column index
     * @return the value
     */
    public Value getOnDuplicateKeyValue(int columnIndex) {
        return onDuplicateKeyRow[columnIndex];
    }

    @Override
    public void collectDependencies(HashSet<DbObject> dependencies) {
        ExpressionVisitor visitor = ExpressionVisitor.getDependenciesVisitor(dependencies);
        if (!valuesExpressionList.isEmpty()) {
            for (Expression[] expr : valuesExpressionList) {
                for (Expression e : expr) {
                    e.isEverything(visitor);
                }
            }
        } else {
            query.isEverything(visitor);
        }
    }
}
