package net.imwork.a166q0w6939.ssltestndk;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class ServShouter {
    private DatagramSocket socket;
    private boolean close;
    private Thread th;

    public ServShouter() {
        close = false;
        th = null;
        try {
            socket = new DatagramSocket(9001);
        } catch (Exception e) {
            socket = null;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        th.interrupt();
        if (socket != null) socket.close();
        super.finalize();
    }

    public void start(final String sign_name) {
        if (th != null) {
            th.interrupt();
        }
        close = false;
        th = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    int count = 0;
                    while (!close && socket != null) {
                        byte[] data = ("SM-DOC-SERV\n" + sign_name).getBytes();
                        DatagramPacket pack = new DatagramPacket(data, data.length, InetAddress.getByName("255.255.255.255"), 9001);
                        socket.send(pack);
                        if (count < 3) {//启动；连发4次
                            count++;
                            continue;
                        }
                        Thread.sleep(5000);//echo 5s
                    }
                } catch (Exception e) {
                    return;
                }
            }
        });
        th.start();
    }

    public void stop() {
        close = true;
    }
}
