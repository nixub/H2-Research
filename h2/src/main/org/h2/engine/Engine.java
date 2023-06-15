/*
 * Copyright 2004-2021 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (https://h2database.com/html/license.html).
 * Initial Developer: H2 Group
 */
package org.h2.engine;

import org.h2.api.ErrorCode;
import org.h2.command.CommandInterface;
import org.h2.command.dml.SetTypes;
import org.h2.message.DbException;
import org.h2.message.Trace;
import org.h2.security.auth.AuthenticationException;
import org.h2.security.auth.AuthenticationInfo;
import org.h2.security.auth.Authenticator;
import org.h2.store.fs.FileUtils;
import org.h2.util.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The engine contains a map of all open databases.
 * It is also responsible for opening and creating new databases.
 * This is a singleton class.
 * 该引擎包含所有打开的数据库的映射。
 *   * 它还负责打开和创建新的数据库。
 *   * 这是一个单例类。
 */
public final class Engine {

    private static final Map<String, DatabaseHolder> DATABASES = new HashMap<>();

    private static volatile long WRONG_PASSWORD_DELAY = SysProperties.DELAY_WRONG_PASSWORD_MIN;

    private static boolean JMX;

    static {
        if (SysProperties.THREAD_DEADLOCK_DETECTOR) {
            ThreadDeadlockDetector.init();
        }
    }

    // 返回一个session
    private static SessionLocal openSession(ConnectionInfo ci, boolean ifExists, boolean forbidCreation,
            String cipher) {
        String name = ci.getName();
        Database database;
        ci.removeProperty("NO_UPGRADE", false);
        boolean openNew = ci.getProperty("OPEN_NEW", false);
        boolean opened = false;
        User user = null;
        DatabaseHolder databaseHolder;
        if (!ci.isUnnamedInMemory()) {
            synchronized (DATABASES) {
                //如果指定的键尚未与值相关联（或映射到 null ），则尝试使用给定的映射函数计算其值，并将其输入到此映射中，除非 null 。
                databaseHolder = DATABASES.computeIfAbsent(name, (key) -> new DatabaseHolder());
            }
        } else {
            databaseHolder = new DatabaseHolder();
        }
        synchronized (databaseHolder) {
            database = databaseHolder.database;
            if (database == null || openNew) {
                if (ci.isPersistent()) {
                    String p = ci.getProperty("MV_STORE");
                    String fileName;
                    if (p == null) {
                        //创建了一个数据库的名字
                        fileName = name + Constants.SUFFIX_MV_FILE;
                        if (!FileUtils.exists(fileName)) {
                            throwNotFound(ifExists, forbidCreation, name);
                            fileName = name + Constants.SUFFIX_OLD_DATABASE_FILE;
                            if (FileUtils.exists(fileName)) {
                                throw DbException.getFileVersionError(fileName);
                            }
                            fileName = null;
                        }
                    } else {
                        fileName = name + Constants.SUFFIX_MV_FILE;
                        if (!FileUtils.exists(fileName)) {
                            throwNotFound(ifExists, forbidCreation, name);
                            fileName = null;
                        }
                    }
                    if (fileName != null && !FileUtils.canWrite(fileName)) {
                        // 访问数据模式 读
                        ci.setProperty("ACCESS_MODE_DATA", "r");
                    }
                } else {
                    throwNotFound(ifExists, forbidCreation, name);
                }
                // 数据库的初始化
                database = new Database(ci, cipher);
                opened = true;
                boolean found = false;
                // 鉴权
                for (RightOwner rightOwner : database.getAllUsersAndRoles()) {
                    if (rightOwner instanceof User) {
                        found = true;
                        break;
                    }
                }
                //如果数据库不存在，那么当前连接server的用户肯定也不存在，所以直接把此用户当成admin，并创建它。
                if (!found) {
                    // users is the last thing we add, so if no user is around,users 是我们添加的最后一件事，所以如果周围没有用户，
                    // the database is new (or not initialized correctly) 数据库是新的（或未正确初始化）
                    user = new User(database, database.allocateObjectId(), ci.getUserName(), false);
                    user.setAdmin(true);
                    user.setUserPasswordHash(ci.getUserPasswordHash());
                    database.setMasterUser(user);
                }
                databaseHolder.database = database;
            }
        }

        if (opened) {
            // start the thread when already synchronizing on the database 已经在数据库上同步时启动线程
            // otherwise a deadlock can occur when the writer thread 否则当写入线程时会发生死锁
            // opens a new database (as in recovery testing) 打开一个新数据库（如在恢复测试中）
            database.opened();
        }
        if (database.isClosing()) {
            return null;
        }
        if (user == null) {
            //检查文件密码哈希是否正确。
            if (database.validateFilePasswordHash(cipher, ci.getFilePasswordHash())) {
                //授权领域
                if (ci.getProperty("AUTHREALM")== null) {
                    user = database.findUser(ci.getUserName());
                    if (user != null) {
                        //检查用户密码是否正确
                        if (!user.validateUserPasswordHash(ci.getUserPasswordHash())) {
                            user = null;
                        }
                    }
                } else {
                    Authenticator authenticator = database.getAuthenticator();
                    if (authenticator==null) {
                        throw DbException.get(ErrorCode.AUTHENTICATOR_NOT_AVAILABLE, name);
                    } else {
                        try {
                            AuthenticationInfo authenticationInfo=new AuthenticationInfo(ci);
                            user = database.getAuthenticator().authenticate(authenticationInfo, database);
                        } catch (AuthenticationException authenticationError) {
                            database.getTrace(Trace.DATABASE).error(authenticationError,
                                "an error occurred during authentication; user: \"" +
                                ci.getUserName() + "\"");
                        }
                    }
                }
            }
            //opened为true说明是是新打开数据库，如果user是null说明用户验证失败
            if (opened && (user == null || !user.isAdmin())) {
                // reset - because the user is not an admin, and has no
                // right to listen to exceptions
                database.setEventListener(null);
            }
        }
        if (user == null) {
            DbException er = DbException.get(ErrorCode.WRONG_USER_OR_PASSWORD);
            database.getTrace(Trace.DATABASE).error(er, "wrong user or password; user: \"" +
                    ci.getUserName() + "\"");
            database.removeSession(null);
            throw er;
        }
        //Prevent to set _PASSWORD 清除身份验证属性。
        ci.cleanAuthenticationInfo();
        //
        checkClustering(ci, database);
        // 得到本地会话对象
        SessionLocal session = database.createSession(user, ci.getNetworkConnectionInfo());
        if (session == null) {
            // concurrently closing
            return null;
        }
        if (ci.getProperty("OLD_INFORMATION_SCHEMA", false)) {
            session.setOldInformationSchema(true);
        }
        if (ci.getProperty("JMX", false)) {
            try {
                Utils.callStaticMethod(
                        "org.h2.jmx.DatabaseInfo.registerMBean", ci, database);
            } catch (Exception e) {
                database.removeSession(session);
                throw DbException.get(ErrorCode.FEATURE_NOT_SUPPORTED_1, e, "JMX");
            }
            JMX = true;
        }
        return session;
    }

    private static void throwNotFound(boolean ifExists, boolean forbidCreation, String name) {
        if (ifExists) {
            throw DbException.get(ErrorCode.DATABASE_NOT_FOUND_WITH_IF_EXISTS_1, name);
        }
        if (forbidCreation) {
            throw DbException.get(ErrorCode.REMOTE_DATABASE_NOT_FOUND_1, name);
        }
    }

    /**
     * Open a database connection with the given connection information. 打开一个数据库连接通过给定的连接信息
     *
     * @param ci the connection information
     * @return the session
     */
    public static SessionLocal createSession(ConnectionInfo ci) {
        try {
            SessionLocal session = openSession(ci);
            validateUserAndPassword(true);
            return session;
        } catch (DbException e) {
            if (e.getErrorCode() == ErrorCode.WRONG_USER_OR_PASSWORD) {
                validateUserAndPassword(false);
            }
            throw e;
        }
    }

    //执行SET和INIT参数中指定的SQL
    private static SessionLocal openSession(ConnectionInfo ci) {
        boolean ifExists = ci.removeProperty("IFEXISTS", false);
        boolean forbidCreation = ci.removeProperty("FORBID_CREATION", false);
        boolean ignoreUnknownSetting = ci.removeProperty(
                "IGNORE_UNKNOWN_SETTINGS", false);
        // 如果设置了 String 属性，则移除它并返回值
        String cipher = ci.removeProperty("CIPHER", null);
        String init = ci.removeProperty("INIT", null);
        SessionLocal session;
        long start = System.nanoTime();
        // 无限循环 只有break throw 才能退出
        for (;;) {
            session = openSession(ci, ifExists, forbidCreation, cipher);
            if (session != null) {
                // 结束循环
                break;
            }
            // we found a database that is currently closing
            // wait a bit to avoid a busy loop (the method is synchronized)
            if (System.nanoTime() - start > DateTimeUtils.NANOS_PER_MINUTE) {
                throw DbException.get(ErrorCode.DATABASE_ALREADY_OPEN_1,
                        "Waited for database closing longer than 1 minute");
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                throw DbException.get(ErrorCode.DATABASE_CALLED_AT_SHUTDOWN);
            }
        }
        synchronized (session) {
            session.setAllowLiterals(true);
            DbSettings defaultSettings = DbSettings.DEFAULT;
            for (String setting : ci.getKeys()) {
                if (defaultSettings.containsKey(setting)) {
                    // database setting are only used when opening the database
                    //中止(跳过)本次循环，接着开始下一次循环
                    continue;
                }
                String value = ci.getProperty(setting);
                StringBuilder builder = new StringBuilder("SET ").append(setting).append(' ');
                // 判断 这是一个简单的标识符吗（在 JDBC 规范意义上）。
                if (!ParserUtil.isSimpleIdentifier(setting, false, false)) {
                    if (!setting.equalsIgnoreCase("TIME ZONE")) {
                        throw DbException.get(ErrorCode.UNSUPPORTED_SETTING_1, setting);
                    }
                    //将字符串转换为 SQL 字符串文字。 Null 转换为
                    //      * 无效的。 如果有特殊字符，Unicode字符串
                    //      * 使用文字。
                    StringUtils.quoteStringSQL(builder, value);
                } else {
                    builder.append(value);
                }
                try {
                    //解析并准备给定的 SQL 语句。
                    //    此方法还检查连接是否已关闭。
                    CommandInterface command = session.prepareLocal(builder.toString());
                    //执行 SQL
                    command.executeUpdate(null);
                } catch (DbException e) {
                    if (e.getErrorCode() == ErrorCode.ADMIN_RIGHTS_REQUIRED) {
                        session.getTrace().error(e, "admin rights required; user: \"" +
                                ci.getUserName() + "\"");
                    } else {
                        session.getTrace().error(e, "");
                    }
                    if (!ignoreUnknownSetting) {
                        session.close();
                        throw e;
                    }
                }
            }
            TimeZoneProvider timeZone = ci.getTimeZone();
            if (timeZone != null) {
                session.setTimeZone(timeZone);
            }
            if (init != null) {
                try {
                    CommandInterface command = session.prepareLocal(init);
                    command.executeUpdate(null);
                } catch (DbException e) {
                    if (!ignoreUnknownSetting) {
                        session.close();
                        throw e;
                    }
                }
            }
            session.setAllowLiterals(false);
            //提交当前事务。 如果语句不是数据
            //       定义语句，如果有临时表应该
            //       在提交时丢弃或截断，这也是完成的。
            session.commit(true);
        }
        return session;
    }

    private static void checkClustering(ConnectionInfo ci, Database database) {
        String clusterSession = ci.getProperty(SetTypes.CLUSTER, null);
        if (Constants.CLUSTERING_DISABLED.equals(clusterSession)) {
            // in this case, no checking is made
            // (so that a connection can be made to disable/change clustering)
            return;
        }
        String clusterDb = database.getCluster();
        if (!Constants.CLUSTERING_DISABLED.equals(clusterDb)) {
            if (!Constants.CLUSTERING_ENABLED.equals(clusterSession)) {
                if (!Objects.equals(clusterSession, clusterDb)) {
                    if (clusterDb.equals(Constants.CLUSTERING_DISABLED)) {
                        throw DbException.get(
                                ErrorCode.CLUSTER_ERROR_DATABASE_RUNS_ALONE);
                    }
                    throw DbException.get(
                            ErrorCode.CLUSTER_ERROR_DATABASE_RUNS_CLUSTERED_1,
                            clusterDb);
                }
            }
        }
    }

    /**
     * Called after a database has been closed, to remove the object from the
     * list of open databases.
     *
     * @param name the database name
     */
    static void close(String name) {
        if (JMX) {
            try {
                Utils.callStaticMethod("org.h2.jmx.DatabaseInfo.unregisterMBean", name);
            } catch (Exception e) {
                throw DbException.get(ErrorCode.FEATURE_NOT_SUPPORTED_1, e, "JMX");
            }
        }
        synchronized (DATABASES) {
            DATABASES.remove(name);
        }
    }

    /**
     * This method is called after validating user name and password. If user
     * name and password were correct, the sleep time is reset, otherwise this
     * method waits some time (to make brute force / rainbow table attacks
     * harder) and then throws a 'wrong user or password' exception. The delay
     * is a bit randomized to protect against timing attacks. Also the delay
     * doubles after each unsuccessful logins, to make brute force attacks
     * harder.
     *
     * There is only one exception message both for wrong user and for
     * wrong password, to make it harder to get the list of user names. This
     * method must only be called from one place, so it is not possible from the
     * stack trace to see if the user name was wrong or the password.
     *
     * @param correct if the user name or the password was correct
     * @throws DbException the exception 'wrong user or password'
     */
    private static void validateUserAndPassword(boolean correct) {
        int min = SysProperties.DELAY_WRONG_PASSWORD_MIN;
        if (correct) {
            long delay = WRONG_PASSWORD_DELAY;
            if (delay > min && delay > 0) {
                // the first correct password must be blocked,
                // otherwise parallel attacks are possible
                synchronized (Engine.class) {
                    // delay up to the last delay
                    // an attacker can't know how long it will be
                    delay = MathUtils.secureRandomInt((int) delay);
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException e) {
                        // ignore
                    }
                    WRONG_PASSWORD_DELAY = min;
                }
            }
        } else {
            // this method is not synchronized on the Engine, so that
            // regular successful attempts are not blocked
            synchronized (Engine.class) {
                long delay = WRONG_PASSWORD_DELAY;
                int max = SysProperties.DELAY_WRONG_PASSWORD_MAX;
                if (max <= 0) {
                    max = Integer.MAX_VALUE;
                }
                WRONG_PASSWORD_DELAY += WRONG_PASSWORD_DELAY;
                if (WRONG_PASSWORD_DELAY > max || WRONG_PASSWORD_DELAY < 0) {
                    WRONG_PASSWORD_DELAY = max;
                }
                if (min > 0) {
                    // a bit more to protect against timing attacks
                    delay += Math.abs(MathUtils.secureRandomLong() % 100);
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException e) {
                        // ignore
                    }
                }
                throw DbException.get(ErrorCode.WRONG_USER_OR_PASSWORD);
            }
        }
    }

    private Engine() {
    }

    private static final class DatabaseHolder {

        DatabaseHolder() {
        }

        volatile Database database;
    }
}
