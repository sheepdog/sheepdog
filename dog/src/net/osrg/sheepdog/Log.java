/*
 * Copyright (C) 2009 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package net.osrg.sheepdog;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.net.SyslogAppender;

public final class Log {
    private static Logger logger = Logger.getLogger("sheepdog");

    private Log() {
    }

    public static Logger getLogger() {
        return logger;
    }

    public static void setLevel(Level level) {
        logger.setLevel(Level.DEBUG);
    }

    private static String format(Object obj) {
        if (obj == null) {
            obj = "null";
        }
        StackTraceElement[] stack = (new Throwable()).getStackTrace();
        String str = obj.toString();
        String thisFile = stack[0].getFileName();
        for (int i = 0; i < stack.length; i++) {
            StackTraceElement frame = stack[i];
            if (!frame.getFileName().equals(thisFile)) {
                return "(" + frame.getFileName() + ":" + frame.getLineNumber()
                        + ") " + str;
            }
        }
        return str;
    }

    public static void debug(Object obj) {
        if (!logger.isDebugEnabled()) {
            return;
        }
        logger.debug(format(obj));
    }

    public static void debug(Object obj, java.lang.Throwable t) {
        if (!logger.isDebugEnabled()) {
            return;
        }
        logger.debug(format(obj), t);
    }

    public static void error(Object obj) {
        logger.error(format(obj));
    }

    public static void error(Object obj, java.lang.Throwable t) {
        logger.error(format(obj), t);
    }

    public static void useSyslog(String syslogHost) {
        SyslogAppender appender = (SyslogAppender) logger.getAppender("syslog");
        appender.setSyslogHost(syslogHost);
        logger.removeAppender("stdout");
    }

    public static void useStdout() {
        logger.removeAppender("syslog");
    }
}
