package net.imwork.a166q0w6939.ssltestndk;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

public class Server {

    public static final byte CMD_UNKNOWN = 0;
    public static final byte CMD_REQ_ENC = 1;
    public static final byte CMD_REQ_DEC = 2;
    public static final byte CMD_RSUCCESS = 3;
    public static final byte CMD_FAILED = 4;
    public static final byte CMD_END = 5;
    public static final byte CMD_HEART = 0x0f;

    static {
        System.loadLibrary("server");
    }

    private long serverCTX;
    private final ArrayList<Session> sessions = new ArrayList<>();
    private boolean stop = false;

    public Server(short port) {
        serverCTX = createServer(port);
    }

    @Override
    protected void finalize() throws Throwable {
        stop = true;
        if (serverCTX != 0) releaseServer(serverCTX);
        super.finalize();
    }

    public void run(ServerCallback callback) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                accept();
            }
        }).start();
        new Thread(new Runnable() {
            @Override
            public void run() {
                heart();
            }
        }).start();
        while (!stop) {
            long[] ss;
            boolean[] mask;
            synchronized (sessions) {//保证select时无任何socket关闭
                if (sessions.size() == 0) continue;
                ss = new long[sessions.size()];
                for (int i = 0; i < sessions.size(); i++) {
                    ss[i] = sessions.get(i).session;
                }
                mask = select(ss);
            }
            for (int i = 0; i < mask.length; i++) {
                if (mask[i]) {
                    Session so;
                    synchronized (sessions) {//寻找session并重置时间
                        so = find(ss[i]);
                        if (so == null) continue;
                        so.time = new Date().getTime();
                    }
                    byte[] buffer = recv(ss[i]);
                    byte command = buffer[0];
                    byte[] hash = new byte[32];
                    System.arraycopy(buffer, 4, hash, 0, 32);
                    byte[] info = new byte[220];
                    System.arraycopy(buffer, 36, info, 0, 220);
                    switch (command) {
                        case CMD_REQ_ENC:
                            so.rhash = hash;
                            try {
                                so.info = new String(info, "UTF-8");
                            } catch (Exception e) {
                                so.info = "";
                            }
                            callback.reqEnc(so, this);
                            break;
                        case CMD_REQ_DEC:
                            so.hash = hash;
                            try {
                                so.info = new String(info, "UTF-8");
                            } catch (Exception e) {
                                so.info = "";
                            }
                            callback.reqDec(so, this);
                            break;
                        case CMD_END:
                            so.hash = hash;
                            callback.finish(so);
                            remove(ss[i]);
                            close(ss[i]);
                            break;
                        case CMD_HEART:
                            break;
                        default:
                            remove(ss[i]);
                            close(ss[i]);
                            break;
                    }
                }
            }
        }
    }

    public void response(long session, byte[] buffer, boolean keep) {
        if (buffer.length != 256) {
            return;
        }
        /*synchronized (sessions) {//保证socket存在
            if (find(session) == null) {
                return;
            }*/
            send(session, buffer);
            /*if (!keep) {
                remove(session);
                close(session);
            }
        }*/
    }

    private void accept() {
        while (!stop) {
            long session = acceptC(serverCTX);
            if (session == 0) continue;
            Session s = new Session();
            s.session = session;
            s.time = new Date().getTime();
            synchronized (sessions) {//同步写
                sessions.add(s);
            }
        }
    }

    private void heart() {
        while (!stop) {
            synchronized (sessions) {//同步心跳检查
                long now = new Date().getTime();
                Iterator<Session> it = sessions.iterator();
                while (it.hasNext()) {
                    Session s = it.next();
                    if (now - s.time > 2000) {
                        it.remove();
                    }
                }
            }
            try {
                Thread.sleep(5000);//5秒一次
            } catch (Exception e) {
            }
        }
    }

    private Session find(long s) {
        synchronized (sessions) {//同步查找
            for (int i = 0; i < sessions.size(); i++) {
                if (sessions.get(i).session == s) {
                    return sessions.get(i);
                }
            }
        }
        return null;
    }

    private void remove(long s) {
        synchronized (sessions) {//同步删除
            for (int i = 0; i < sessions.size(); i++) {
                if (sessions.get(i).session == s) {
                    sessions.remove(i);
                    break;
                }
            }
        }
    }

    private native long createServer(short port);

    private native void releaseServer(long ctx);

    private native long acceptC(long ctx);

    private native boolean[] select(long[] ss);

    private native byte[] recv(long s);

    private native void send(long s, byte[] buf);

    private native void close(long s);

    private native String getErr();

    public class Session {
        long session = 0;
        String info = null;
        byte[] keyiv = null;
        byte[] rhash = null;
        byte[] hash = null;
        long time = 0;
    }
}
