/*
 * Copyright 2004-2021 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (https://h2database.com/html/license.html).
 * Initial Developer: H2 Group
 */
package org.h2.command;

import org.h2.api.DatabaseEventListener;
import org.h2.api.ErrorCode;
import org.h2.command.ddl.DefineCommand;
import org.h2.command.dml.DataChangeStatement;
import org.h2.engine.Database;
import org.h2.engine.DbObject;
import org.h2.engine.DbSettings;
import org.h2.engine.SessionLocal;
import org.h2.expression.Expression;
import org.h2.expression.ExpressionColumn;
import org.h2.expression.Parameter;
import org.h2.expression.ParameterInterface;
import org.h2.index.Index;
import org.h2.message.DbException;
import org.h2.result.LocalResult;
import org.h2.result.ResultInterface;
import org.h2.result.ResultTarget;
import org.h2.result.ResultWithGeneratedKeys;
import org.h2.table.Column;
import org.h2.table.DataChangeDeltaTable.ResultOption;
import org.h2.table.Table;
import org.h2.table.TableView;
import org.h2.util.StringUtils;
import org.h2.util.Utils;
import org.h2.value.Value;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Represents a single SQL statements.
 * It wraps a prepared statement.
 *
 * 表示单个SQL 语句，他包装了一个准备好的语句
 */
public class CommandContainer extends Command {

    /**
     * Collector of generated keys.
     *
     * 生成秘钥收集器
     */
    private static final class GeneratedKeysCollector implements ResultTarget {

        private final int[] indexes;
        private final LocalResult result;

        GeneratedKeysCollector(int[] indexes, LocalResult result) {
            this.indexes = indexes;
            this.result = result;
        }

        @Override
        public void limitsWereApplied() {
            // Nothing to do
        }

        @Override
        public long getRowCount() {
            // Not required
            return 0L;
        }

        @Override
        public void addRow(Value... values) {
            int length = indexes.length;
            Value[] row = new Value[length];
            for (int i = 0; i < length; i++) {
                row[i] = values[indexes[i]];
            }
            result.addRow(row);
        }

    }

    private Prepared prepared;
    private boolean readOnlyKnown;
    private boolean readOnly;

    /**
     * Clears CTE views for a specified statement.
     *
     * @param session the session
     * @param prepared prepared statement
     */
    static void clearCTE(SessionLocal session, Prepared prepared) {
        List<TableView> cteCleanups = prepared.getCteCleanups();
        if (cteCleanups != null) {
            clearCTE(session, cteCleanups);
        }
    }

    /**
     * Clears CTE views.
     *
     * @param session the session
     * @param views list of view
     */
    static void clearCTE(SessionLocal session, List<TableView> views) {
        for (TableView view : views) {
            // check if view was previously deleted as their name is set to
            // null
            if (view.getName() != null) {
                session.removeLocalTempTable(view);
            }
        }
    }

    public CommandContainer(SessionLocal session, String sql, Prepared prepared) {
        super(session, sql);
        prepared.setCommand(this);
        this.prepared = prepared;
    }

    @Override
    public ArrayList<? extends ParameterInterface> getParameters() {
        return prepared.getParameters();
    }

    @Override
    public boolean isTransactional() {
        return prepared.isTransactional();
    }

    @Override
    public boolean isQuery() {
        return prepared.isQuery();
    }

    //重新解析并prepare
    private void recompileIfRequired() {
        if (prepared.needRecompile()) {
            // TODO test with 'always recompile'
            prepared.setModificationMetaId(0);
            String sql = prepared.getSQL();
            ArrayList<Parameter> oldParams = prepared.getParameters();
            Parser parser = new Parser(session);
            prepared = parser.parse(sql);
            long mod = prepared.getModificationMetaId();
            prepared.setModificationMetaId(0);
            ArrayList<Parameter> newParams = prepared.getParameters();
            for (int i = 0, size = newParams.size(); i < size; i++) {
                Parameter old = oldParams.get(i);
                if (old.isValueSet()) {
                    Value v = old.getValue(session);
                    Parameter p = newParams.get(i);
                    p.setValue(v);
                }
            }
            prepared.prepare();
            prepared.setModificationMetaId(mod);
        }
    }

    @Override
    public ResultWithGeneratedKeys update(Object generatedKeysRequest) {
        //重新解析并prepare
        recompileIfRequired();
        //设置长时间操作的进度
        setProgress(DatabaseEventListener.STATE_STATEMENT_START);
        //开始计算操作耗时
        start();
        //检测预处理语句的参数
        prepared.checkParameters();

        ResultWithGeneratedKeys result;
        if (generatedKeysRequest != null && !Boolean.FALSE.equals(generatedKeysRequest)) {
            //判断预处理语句的类型。
            if (prepared instanceof DataChangeStatement && prepared.getType() != CommandInterface.DELETE) {
                result = executeUpdateWithGeneratedKeys((DataChangeStatement) prepared,
                        generatedKeysRequest);
            } else {
                result = new ResultWithGeneratedKeys.WithKeys(prepared.update(), new LocalResult());
            }
        } else {
            result = ResultWithGeneratedKeys.of(prepared.update());
        }
        prepared.trace(startTimeNanos, result.getUpdateCount());
        setProgress(DatabaseEventListener.STATE_STATEMENT_END);
        return result;
    }

    private ResultWithGeneratedKeys executeUpdateWithGeneratedKeys(DataChangeStatement statement,
            Object generatedKeysRequest) {
        Database db = session.getDatabase();
        Table table = statement.getTable();
        ArrayList<ExpressionColumn> expressionColumns;
        if (Boolean.TRUE.equals(generatedKeysRequest)) {
            expressionColumns = Utils.newSmallArrayList();
            Column[] columns = table.getColumns();
            Index primaryKey = table.findPrimaryKey();
            for (Column column : columns) {
                Expression e;
                if (column.isIdentity()
                        || ((e = column.getEffectiveDefaultExpression()) != null && !e.isConstant())
                        || (primaryKey != null && primaryKey.getColumnIndex(column) >= 0)) {
                    expressionColumns.add(new ExpressionColumn(db, column));
                }
            }
        } else if (generatedKeysRequest instanceof int[]) {
            int[] indexes = (int[]) generatedKeysRequest;
            Column[] columns = table.getColumns();
            int cnt = columns.length;
            expressionColumns = new ArrayList<>(indexes.length);
            for (int idx : indexes) {
                if (idx < 1 || idx > cnt) {
                    throw DbException.get(ErrorCode.COLUMN_NOT_FOUND_1, "Index: " + idx);
                }
                expressionColumns.add(new ExpressionColumn(db, columns[idx - 1]));
            }
        } else if (generatedKeysRequest instanceof String[]) {
            String[] names = (String[]) generatedKeysRequest;
            expressionColumns = new ArrayList<>(names.length);
            for (String name : names) {
                Column column = table.findColumn(name);
                if (column == null) {
                    DbSettings settings = db.getSettings();
                    if (settings.databaseToUpper) {
                        column = table.findColumn(StringUtils.toUpperEnglish(name));
                    } else if (settings.databaseToLower) {
                        column = table.findColumn(StringUtils.toLowerEnglish(name));
                    }
                    search: if (column == null) {
                        for (Column c : table.getColumns()) {
                            if (c.getName().equalsIgnoreCase(name)) {
                                column = c;
                                break search;
                            }
                        }
                        throw DbException.get(ErrorCode.COLUMN_NOT_FOUND_1, name);
                    }
                }
                expressionColumns.add(new ExpressionColumn(db, column));
            }
        } else {
            throw DbException.getInternalError();
        }
        int columnCount = expressionColumns.size();
        if (columnCount == 0) {
            return new ResultWithGeneratedKeys.WithKeys(statement.update(), new LocalResult());
        }
        int[] indexes = new int[columnCount];
        ExpressionColumn[] expressions = expressionColumns.toArray(new ExpressionColumn[0]);
        for (int i = 0; i < columnCount; i++) {
            indexes[i] = expressions[i].getColumn().getColumnId();
        }
        LocalResult result = new LocalResult(session, expressions, columnCount, columnCount);
        return new ResultWithGeneratedKeys.WithKeys(
                statement.update(new GeneratedKeysCollector(indexes, result), ResultOption.FINAL), result);
    }

    @Override
    public ResultInterface query(long maxrows) {
        //
        recompileIfRequired();
        setProgress(DatabaseEventListener.STATE_STATEMENT_START);
        start();
        prepared.checkParameters();
        ResultInterface result = prepared.query(maxrows);
        prepared.trace(startTimeNanos, result.isLazy() ? 0 : result.getRowCount());
        setProgress(DatabaseEventListener.STATE_STATEMENT_END);
        return result;
    }

    @Override
    public void stop() {
        super.stop();
        // Clean up after the command was run in the session.
        // Must restart query (and dependency construction) to reuse.
        clearCTE(session, prepared);
    }

    @Override
    public boolean canReuse() {
        return super.canReuse() && prepared.getCteCleanups() == null;
    }

    @Override
    public boolean isReadOnly() {
        // call和select这两个语句对应的isReadOnly()会调用Expression.isEverything,
        // 是一个有点耗时的事，所以最好只调用一次
        if (!readOnlyKnown) {
            readOnly = prepared.isReadOnly();
            readOnlyKnown = true;
        }
        return readOnly;
    }

    @Override
    public ResultInterface queryMeta() {
        return prepared.queryMeta();
    }

    @Override
    public boolean isCacheable() {
        return prepared.isCacheable();
    }

    @Override
    public int getCommandType() {
        return prepared.getType();
    }

    /**
     * Clean up any associated CTE.
     */
    void clearCTE() {
        clearCTE(session, prepared);
    }

    @Override
    public Set<DbObject> getDependencies() {
        HashSet<DbObject> dependencies = new HashSet<>();
        prepared.collectDependencies(dependencies);
        return dependencies;
    }

    @Override
    protected boolean isCurrentCommandADefineCommand() {
        return prepared instanceof DefineCommand;
    }
}
