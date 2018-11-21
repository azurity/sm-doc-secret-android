package net.imwork.a166q0w6939.ssltestndk;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Base64;

public class DBop extends SQLiteOpenHelper {
    private static final int DB_VERSION = 1;
    private static final String DB_NAME = "session.db";
    private static final String TABLE_NAME = "session";


    public DBop(Context context) {
        super(context, DB_NAME, null, 1);
    }

    @Override
    public void onCreate(SQLiteDatabase sqLiteDatabase) {
        String sql = "create table if not exists " + TABLE_NAME + "(info text,keyiv text,hash text primary key,rhash text)";
        sqLiteDatabase.execSQL(sql);
    }

    @Override
    public void onUpgrade(SQLiteDatabase sqLiteDatabase, int i, int i1) {
        //升级清库
        String sql = "drop table if exists " + TABLE_NAME;
        sqLiteDatabase.execSQL(sql);
        onCreate(sqLiteDatabase);
    }

    public int getCount() {
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.query(TABLE_NAME,
                new String[]{"hash"},
                null, null, null, null, null);
        return cursor.getCount();
    }

    public boolean saveSession(Server.Session s) {
        SQLiteDatabase rdb = getReadableDatabase();
        Cursor cursor = rdb.query(TABLE_NAME,
                new String[]{"hash"},
                "hash = ?",
                new String[]{Base64.encodeToString(s.rhash, Base64.DEFAULT)},
                null, null, null);
        if (cursor.getCount() != 0) {
            cursor.close();
            return false;
        }
        SQLiteDatabase wdb = getWritableDatabase();
        wdb.beginTransaction();
        ContentValues cval = new ContentValues();
        cval.put("info", Base64.encodeToString(s.info.getBytes(), Base64.DEFAULT));
        cval.put("keyiv", Base64.encodeToString(s.keyiv, Base64.DEFAULT));
        cval.put("hash", Base64.encodeToString(s.hash, Base64.DEFAULT));
        cval.put("rhash", Base64.encodeToString(s.rhash, Base64.DEFAULT));
        wdb.insertOrThrow(TABLE_NAME, null, cval);
        wdb.setTransactionSuccessful();
        wdb.endTransaction();
        return true;
    }

    public boolean getSession(byte[] hash, byte[] keyiv, byte[] rhash) {
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.query(TABLE_NAME,
                new String[]{"keyiv", "rhash"},
                "hash = ?",
                new String[]{Base64.encodeToString(hash, Base64.DEFAULT)},
                null, null, null);
        if (cursor.getCount() == 0) {
            cursor.close();
            return false;
        }
        cursor.moveToFirst();
        byte[] ki = Base64.decode(cursor.getString(0), Base64.DEFAULT);
        System.arraycopy(ki, 0, keyiv, 0, 32);
        byte[] rh = Base64.decode(cursor.getString(1), Base64.DEFAULT);
        System.arraycopy(rh, 0, rhash, 0, 32);
        cursor.close();
        return true;
    }
}
