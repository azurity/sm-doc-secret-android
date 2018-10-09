package net.imwork.a166q0w6939.ssltestndk;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    private static final int PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE = 1;

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        checkPermission();

        // Example of a call to a native method
    }

    private void work() {
        final TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText(stringFromJNI());
        final Server s = new Server((short) 9000);
        new Thread(new Runnable() {
            @Override
            public void run() {
                s.run(new ServerCallback() {
                    @Override
                    public void reqEnc(Server.Session s, Server server) {
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                String str = "REQ_ENC";
                                tv.setText(str);
                            }
                        });
                        byte[] ret = new byte[256];
                        ret[0] = Server.CMD_FAILED;
                        server.response(s.session, ret, true);
                        return;
                    }

                    @Override
                    public void reqDec(Server.Session s, Server server) {
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                String str = "REQ_DEC";
                                tv.setText(str);
                            }
                        });
                        byte[] ret = new byte[256];
                        ret[0] = Server.CMD_FAILED;
                        server.response(s.session, ret, false);
                        return;
                    }

                    @Override
                    public void finish(Server.Session s) {
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                String str = "END";
                                tv.setText(str);
                            }
                        });
                    }
                });
            }
        }).start();

        /*final int sock = createSocket();
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String s = accept(sock);
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        tv.setText(s);
                    }
                });
            }
        }).start();*/
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        if (requestCode == PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE) {
            work();
        }
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }

    Handler handler = new Handler();

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    public native int createSocket();

    public native String accept(int socket);

    private void checkPermission() {
        //检查权限（NEED_PERMISSION）是否被授权 PackageManager.PERMISSION_GRANTED表示同意授权
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
            //用户已经拒绝过一次，再次弹出权限申请对话框需要给用户一个解释
            if (ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission
                    .WRITE_EXTERNAL_STORAGE)) {
                Toast.makeText(this, "请开通相关权限，否则无法正常使用本应用！", Toast.LENGTH_SHORT).show();
            }
            //申请权限
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE);

        } else {
            Toast.makeText(this, "授权成功！", Toast.LENGTH_SHORT).show();
            work();
        }
    }
}
