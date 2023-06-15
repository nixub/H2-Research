/*
 * Copyright 2004-2021 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (https://h2database.com/html/license.html).
 * Initial Developer: H2 Group
 */
package org.h2.fulltext;

/**
 * The settings of one full text search index. 一个全文搜索索引的设置。
 */
public class IndexInfo {

    /**
     * The index id.
     */
    protected int id;

    /**
     * The schema name.
     */
    protected String schema;

    /**
     * The table name.
     */
    protected String table;

    /**
     * The column indexes of the key columns.  键列的列索引
     */
    protected int[] keys;

    /**
     * The column indexes of the index columns.  索引列的列索引。
     */
    protected int[] indexColumns;

    /**
     * The column names.   列名称
     */
    protected String[] columns;
}
