/*
 * Copyright 2004-2021 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (https://h2database.com/html/license.html).
 * Initial Developer: H2 Group
 */
package org.h2.mvstore.tx;

import java.util.BitSet;

/**
 * Class VersionedBitSet extends standard BitSet to add a version field.
 * This will allow bit set and version to be changed atomically.
 * 类 VersionedBitSet 扩展标准 BitSet 以添加版本字段。
 *   * 这将允许自动更改位集和版本。
 */
final class VersionedBitSet extends BitSet {
    private static final long serialVersionUID = 1L;

    private long version;

    public VersionedBitSet() {}

    public long getVersion() {
        return version;
    }

    public void setVersion(long version) {
        this.version = version;
    }

    @Override
    public VersionedBitSet clone() {
        return (VersionedBitSet)super.clone();
    }
}
