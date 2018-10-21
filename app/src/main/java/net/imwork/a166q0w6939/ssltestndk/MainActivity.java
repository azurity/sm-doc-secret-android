package net.imwork.a166q0w6939.ssltestndk;

import android.Manifest;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.security.SecureRandom;

public class MainActivity extends AppCompatActivity {

    private static final int PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE = 1;

    private ServShouter shouter;

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    private final DBop db = new DBop(this);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        checkPermission();


        // Example of a call to a native method
    }

    private void waitStart() {
        final MainActivity ctx = this;
        Button btn = (Button) findViewById(R.id.button);
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                TextView sign = findViewById(R.id.editText);
                String sign_name = sign.getText().toString().trim();
                if (sign_name == "") {
                    Toast.makeText(ctx, "请输入识别名", Toast.LENGTH_SHORT).show();
                } else {
                    if(sign_name.length()>12) {
                        sign_name = sign_name.substring(0, 12);
                    }
                    work(sign_name);
                }
            }
        });
    }

    private void work(final String sign_name) {
        shouter = new ServShouter();
        shouter.start(sign_name);
        final TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText("Working");

        final Context context = this;
        final Server s = new Server((short) 9000);
        new Thread(new Runnable() {
            @Override
            public void run() {
                s.run(new ServerCallback() {
                    @Override
                    public void reqEnc(final Server.Session s, final Server server) {
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                String str = "REQ_ENC";
                                tv.setText(str);
                                String[] arr = s.info.split("\n");
                                String username = arr[0];
                                String filename = arr[1];
                                s.info = username + "\n" + filename;
                                new AlertDialog.Builder(context).setTitle("encryptfile from:" + username + "\nfile:" + filename).setPositiveButton("yes",
                                        new DialogInterface.OnClickListener() {
                                            @Override
                                            public void onClick(DialogInterface dialog, int which) {
                                                TextView tv = (TextView) findViewById(R.id.sample_text);
                                                tv.setText("start to encrypt!");
                                                final byte[] ret = new byte[256];// async cannt be placed outside
                                                byte[] keyiv = new byte[32];
                                                new SecureRandom().nextBytes(keyiv);
                                                s.keyiv = keyiv;
                                                ret[0] = Server.CMD_RSUCCESS;
                                                System.arraycopy(keyiv, 0, ret, 4, 32);
                                                new Thread(new Runnable() {
                                                    @Override
                                                    public void run() {
                                                        server.response(s.session, ret, true);
                                                    }
                                                }).start();
                                            }
                                        }).setNegativeButton("no",
                                        new DialogInterface.OnClickListener() {
                                            @Override
                                            public void onClick(DialogInterface dialog, int which) {
                                                TextView tv = (TextView) findViewById(R.id.sample_text);
                                                tv.setText("refused to encrypt!");
                                                final byte[] ret = new byte[256];
                                                ret[0] = Server.CMD_FAILED;
                                                new Thread(new Runnable() {
                                                    @Override
                                                    public void run() {
                                                        server.response(s.session, ret, true);
                                                    }
                                                }).start();
                                            }
                                        }).show();
                            }
                        });
                        return;
                    }

                    @Override
                    public void reqDec(final Server.Session s, final Server server) {
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                String str = "REQ_DEC";
                                tv.setText(str);
                                String[] arr = s.info.split("\n");
                                String username = arr[0];
                                String filename = arr[1];
                                s.info = username + "\n" + filename;
                                new AlertDialog.Builder(context).setTitle("decrypt from:\n" + username + "\n" + filename).setPositiveButton("yes",
                                        new DialogInterface.OnClickListener() {
                                            @Override
                                            public void onClick(DialogInterface dialog, int which) {
                                                TextView tv = (TextView) findViewById(R.id.sample_text);
                                                tv.setText("start to decrypt!");
                                                final byte[] ret = new byte[256];
                                                byte[] keyiv = new byte[32];
                                                byte[] rhash = new byte[32];

                                                if (!db.getSession(s.hash, keyiv, rhash)) {
                                                    ret[0] = Server.CMD_FAILED;
                                                } else {
                                                    ret[0] = Server.CMD_RSUCCESS;
                                                    System.arraycopy(keyiv, 0, ret, 4, 32);
                                                    System.arraycopy(rhash, 0, ret, 36, 32);
                                                }
                                                new Thread(new Runnable() {
                                                    @Override
                                                    public void run() {
                                                        server.response(s.session, ret, false);
                                                    }
                                                }).start();
                                            }
                                        }).setNegativeButton("no",
                                        new DialogInterface.OnClickListener() {
                                            @Override
                                            public void onClick(DialogInterface dialog, int which) {
                                                TextView tv = (TextView) findViewById(R.id.sample_text);
                                                tv.setText("refused to decrypt!");
                                                final byte[] ret = new byte[256];
                                                ret[0] = Server.CMD_FAILED;
                                                new Thread(new Runnable() {
                                                    @Override
                                                    public void run() {
                                                        server.response(s.session, ret, false);
                                                    }
                                                }).start();
                                            }
                                        }).show();
                            }
                        });
                        return;
                    }

                    @Override
                    public void finish(final Server.Session s) {
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                String str = "END";
                                tv.setText(str);
                                if (!db.saveSession(s)) {
                                    handler.post(new Runnable() {
                                        @Override
                                        public void run() {
                                            Toast.makeText(context, "Save failed!", Toast.LENGTH_SHORT).show();
                                        }
                                    });
                                } else {
                                    handler.post(new Runnable() {
                                        @Override
                                        public void run() {
                                            Toast.makeText(context, "encrypt finish", Toast.LENGTH_SHORT).show();
                                        }
                                    });
                                }
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
            waitStart();
            //work();
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
            waitStart();
            //work();
        }
    }
}
