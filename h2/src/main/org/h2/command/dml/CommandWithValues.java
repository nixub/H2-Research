/*
 * Copyright 2004-2021 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (https://h2database.com/html/license.html).
 * Initial Developer: H2 Group
 */
package org.h2.command.dml;

import org.h2.engine.SessionLocal;
import org.h2.expression.Expression;
import org.h2.util.Utils;

import java.util.ArrayList;

/**
 * Command that supports VALUES clause.支持 VALUES 子句的命令。
 */
public abstract class CommandWithValues extends DataChangeStatement {

    /**
     * Expression data for the VALUES clause.
     */
    protected final ArrayList<Expression[]> valuesExpressionList = Utils.newSmallArrayList();

    /**
     * Creates new instance of command with VALUES clause.
     *
     * @param session
     *            the session
     */
    protected CommandWithValues(SessionLocal session) {
        super(session);
    }

    /**
     * Add a row to this command.
     *
     * @param expr
     *            the list of values
     */
    public void addRow(Expression[] expr) { //一行的各字段值组成的数组
        valuesExpressionList.add(expr);
    }

}
