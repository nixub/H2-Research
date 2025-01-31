/*
 * Copyright 2004-2021 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (https://h2database.com/html/license.html).
 * Initial Developer: H2 Group
 */
package org.h2.mvstore;

/**
 * A position in a cursor.
 * Instance represents a node in the linked list, which traces path
 * from a specific (target) key within a leaf node all the way up to te root
 * (bottom up path).
 * 游标中的一个位置。
 *  Instance代表链表中的一个节点，它追踪路径
 *  从叶节点中的特定（目标）键一直到根
 *  自下而上的路径）。
 */
//遍历B-Tree时通过它能向上或向右指定节点
public final class CursorPos<K,V> {

    /**
     * The page at the current level. 页的当前层级
     */
    public Page<K,V> page;

    /**
     * Index of the key (within page above) used to go down to a lower level
     * in case of intermediate nodes, or index of the target key for leaf a node.
     * In a later case, it could be negative, if the key is not present.
     */
    public int index;

    /**
     * Next node in the linked list, representing the position within parent level,
     * or null, if we are at the root level already.
     */
    public CursorPos<K,V> parent;


    public CursorPos(Page<K,V> page, int index, CursorPos<K,V> parent) {
        this.page = page;
        this.index = index;
        this.parent = parent;
    }

    /**
     * Searches for a given key and creates a breadcrumb trail through a B-tree
     * rooted at a given Page. Resulting path starts at "insertion point" for a
     * given key and goes back to the root.
     * 搜索给定的键并通过 B 树创建面包屑路径
     *       *植根于给定的页面。 结果路径从“插入点”开始
     *       * 给定密钥并返回到根。
     *
     * @param page      root of the tree
     * @param key       the key to search for
     * @return head of the CursorPos chain (insertion point)
     */
    static <K,V> CursorPos<K,V> traverseDown(Page<K,V> page, K key) {
        CursorPos<K,V> cursorPos = null;
        while (!page.isLeaf()) {
            int index = page.binarySearch(key) + 1;
            if (index < 0) {
                index = -index;
            }
            cursorPos = new CursorPos<>(page, index, cursorPos);
            page = page.getChildPage(index);
        }
        return new CursorPos<>(page, page.binarySearch(key), cursorPos);
    }

    /**
     * Calculate the memory used by changes that are not yet stored.
     *
     * @param version the version
     * @return the amount of memory
     */
    int processRemovalInfo(long version) {
        int unsavedMemory = 0;
        for (CursorPos<K,V> head = this; head != null; head = head.parent) {
            unsavedMemory += head.page.removePage(version);
        }
        return unsavedMemory;
    }

    @Override
    public String toString() {
        return "CursorPos{" +
                "page=" + page +
                ", index=" + index +
                ", parent=" + parent +
                '}';
    }
}

