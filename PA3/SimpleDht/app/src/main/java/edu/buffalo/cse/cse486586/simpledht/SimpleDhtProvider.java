package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Formatter;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

import org.w3c.dom.Node;

public class SimpleDhtProvider extends ContentProvider {

    static final String TAG = SimpleDhtProvider.class.getName();
    static final int SERVER_PORT = 10000;

    static final ArrayList<String> PORTS = new ArrayList<String>(Arrays.asList("5554", "5556", "5558", "5560", "5562"));
    static Ring ring = new Ring();
    static boolean FLAG = true;

    Uri mUri = buildUri("content", "edu.buffalo.cse.cse486586.simpledht.provider");

    static String CURRENT_PORT;
    static String MAXIMUM_HASH;

    static ArrayList<String> fileStored = new ArrayList<String>();

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        int response = 0;
        try {
            if(selection.equals("@")) {
                for (String file : fileStored) {
                    getContext().deleteFile(file);
                    response += 1;
                }
            } else if (selection.equals("*")) {
                if (ring.getID().compareTo(ring.getFrontNode()) == 0
                        || selection.contains(ring.successor)
                ) {
                    for (String file : fileStored) {
                        getContext().deleteFile(file);
                        response += 1;
                    }
                } else {
                    Socket client = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(ring.successor) * 2);

                    PrintWriter msgSend = new PrintWriter(client.getOutputStream(), true);
                    BufferedReader ackGet = new BufferedReader(new InputStreamReader(client.getInputStream()));
                    msgSend.println("PRADEEP1:" + selection);

                    while (!client.isClosed()) {
                        String ack = ackGet.readLine();

                        if(ack.contains("DELETED")) {
                            response = Integer.parseInt(ack.split(":")[1]);
                        }
                        client.close();
                    }

                    for(String file : fileStored) {
                        getContext().deleteFile(file);
                        response += 1;
                    }
                }
            } else {
                String hashFileName = genHash(selection);

                if((ring.getID().compareTo(ring.getBackNode()) > 0
                        && hashFileName.compareTo(ring.getBackNode()) > 0
                        && hashFileName.compareTo(ring.getID()) <= 0)
                        || (ring.getID().compareTo(ring.getBackNode()) < 0
                        && ((hashFileName.compareTo(ring.getBackNode()) > 0
                        && hashFileName.compareTo(ring.getID()) > 0)
                        || (hashFileName.compareTo(ring.getBackNode()) < 0
                        && hashFileName.compareTo(ring.getID()) <= 0)))
                        || (ring.getID().compareTo(ring.getBackNode()) == 0
                        && ring.getID().compareTo(ring.getFrontNode()) == 0)
                ) {
                    getContext().deleteFile(selection);
                    response = 1;
                } else {
                    Socket client = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(ring.successor) * 2);

                    PrintWriter msgSend = new PrintWriter(client.getOutputStream(), true);
                    BufferedReader ackGet = new BufferedReader(new InputStreamReader(client.getInputStream()));
                    msgSend.println("PRADEEP1:" + selection);

                    while (!client.isClosed()) {
                        String ack = ackGet.readLine();

                        if(ack.contains("DELETED")) {
                            response = Integer.parseInt(ack.split(":")[1]);
                        }
                        client.close();
                    }
                }
            }
        }
        catch (Exception exception) {
            Log.e(TAG, exception.getMessage());
        }
        return response;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        try {
            String hashFileName = genHash((String) values.get("key"));
            if(
                    (
                            ring.getID().compareTo(ring.getBackNode()) > 0
                            &&
                            hashFileName.compareTo(ring.getBackNode()) > 0
                            &&
                            hashFileName.compareTo(ring.getID()) <= 0
                    )
                    ||
                    (
                            ring.getID().compareTo(ring.getBackNode()) < 0
                            &&
                            (
                                    (
                                            hashFileName.compareTo(ring.getBackNode()) > 0
                                            &&
                                            hashFileName.compareTo(ring.getID()) > 0
                                    )
                                    ||
                                    (
                                            hashFileName.compareTo(ring.getBackNode()) < 0
                                            &&
                                            hashFileName.compareTo(ring.getID()) <= 0
                                    )
                            )
                    )
                    ||
                    (
                            ring.getID().compareTo(ring.getBackNode()) == 0
                            && ring.getID().compareTo(ring.getFrontNode()) == 0
                    )
            ) {

                FileOutputStream outputStream = getContext().openFileOutput((String) values.get("key"), Context.MODE_PRIVATE);
                String value = (String) values.get("value");
                outputStream.write(value.getBytes());
                outputStream.close();
                fileStored.add((String) values.get("key"));
            } else {
                Socket client = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(ring.successor) * 2);

                PrintWriter msgSend = new PrintWriter(client.getOutputStream(), true);
                msgSend.println("PRADEEP2:" + values.get("key") + ":" + values.get("value"));
            }
        } catch (Exception exception) {
            Log.e(TAG, "Pradeep_Insert : " + exception.getMessage());
        }
        return uri;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {
        if(!selection.contains("PORT_")){
            selection = "PORT_" + CURRENT_PORT + "&" + selection;
        }

        MatrixCursor matrixCursor = new MatrixCursor(new String[]{"key", "value"});
        try {
            if (selection.split("&")[1].equals("@")) {
                for(String file : fileStored) {
                    FileInputStream inputStream = getContext().openFileInput(file);
                    byte[] content = new byte[50];

                    int length = inputStream.read(content);

                    String value = new String(content).substring(0, length);
                    MatrixCursor.RowBuilder mRowBuilder = matrixCursor.newRow();

                    mRowBuilder.add("key", file);
                    mRowBuilder.add("value", value);

                    inputStream.close();
                }
            } else if (selection.split("&")[1].equals("*")) {
                if(ring.getID().compareTo(ring.getFrontNode()) == 0
                        || selection.contains(ring.successor)) {

                    for(String file : fileStored) {
                        FileInputStream inputStream = getContext().openFileInput(file);
                        byte[] content = new byte[50];

                        int size = inputStream.read(content);

                        String value = new String(content).substring(0, size);
                        MatrixCursor.RowBuilder mRowBuilder = matrixCursor.newRow();

                        mRowBuilder.add("key", file);
                        mRowBuilder.add("value", value);

                        inputStream.close();
                    }
                } else {
                    Socket client = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(ring.successor) * 2);

                    PrintWriter writer = new PrintWriter(client.getOutputStream(), true);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
                    writer.println("PRADEEP3:" + selection);
                    String[] values = null;

                    while (!client.isClosed()) {
                        String ack = reader.readLine();

                        if(ack.length() > ("QUERY-").length()){
                            values = ack.split("-")[1].split(":");
                        }
                        client.close();
                    }

                    for(int index = 0; values != null && values.length > 0 && index < values.length; index += 2) {
                        MatrixCursor.RowBuilder mRowBuilder = matrixCursor.newRow();
                        mRowBuilder.add("key", values[index]);
                        mRowBuilder.add("value", values[index + 1]);
                    }

                    MatrixCursor localCursor = new MatrixCursor(new String[]{"key", "value"});

                    for(String file : fileStored) {
                        FileInputStream inputStream = getContext().openFileInput(file);
                        byte[] content = new byte[50];

                        int length = inputStream.read(content);

                        String value = new String(content).substring(0, length);
                        MatrixCursor.RowBuilder mRowBuilder = localCursor.newRow();

                        mRowBuilder.add("key", file);
                        mRowBuilder.add("value", value);

                        inputStream.close();
                    }

                    String val = "";
                    int first = localCursor.getColumnIndex("key");
                    int second = localCursor.getColumnIndex("value");
                    localCursor.moveToFirst();
                    if (localCursor.getCount() > 0) {
                        do {
                            val += localCursor.getString(first) + ":" + localCursor.getString(second) + ":";
                        } while (localCursor.moveToNext());

                        localCursor.close();
                        if (val.length() > 0) {
                            val = val.substring(0, val.length() - 1);
                        }
                    }

                    String[] data = val.split(":");

                    for (int index = 0; index + 1 < data.length; index +=2) {
                        MatrixCursor.RowBuilder mRowBuilder = matrixCursor.newRow();
                        mRowBuilder.add("key", data[index]);
                        mRowBuilder.add("value", data[index + 1]);
                    }
                }
            } else {
                String hashFileName = genHash(selection.split("&")[1]);
                if((ring.getID().compareTo(ring.getBackNode()) > 0
                        && hashFileName.compareTo(ring.getBackNode()) > 0
                        && hashFileName.compareTo(ring.getID()) <= 0)
                        || (ring.getID().compareTo(ring.getBackNode()) < 0
                        && ((hashFileName.compareTo(ring.getBackNode()) > 0
                        && hashFileName.compareTo(ring.getID()) > 0)
                        || (hashFileName.compareTo(ring.getBackNode()) < 0
                        && hashFileName.compareTo(ring.getID()) <= 0)))
                        || (ring.getID().compareTo(ring.getBackNode()) == 0
                        && ring.getID().compareTo(ring.getFrontNode()) == 0)) {

                    FileInputStream inputStream = getContext().openFileInput(selection.split("&")[1]);
                    byte[] content = new byte[50];

                    int length = inputStream.read(content);

                    String value = new String(content).substring(0, length);
                    MatrixCursor.RowBuilder mRowBuilder = matrixCursor.newRow();

                    mRowBuilder.add("key", selection.split("&")[1]);
                    mRowBuilder.add("value", value);

                    inputStream.close();
                } else {
                    Socket client = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(ring.successor) * 2);

                    PrintWriter writer = new PrintWriter(client.getOutputStream(), true);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
                    writer.println("PRADEEP3:" + selection);
                    String[] values = null;

                    while (!client.isClosed()) {
                        String ack = reader.readLine();

                        if(ack.length() > ("QUERY-").length()){
                            values = ack.split("-")[1].split(":");
                        }
                        client.close();
                    }

                    for(int index = 0; values != null && values.length > 0 && index < values.length; index += 2) {
                        MatrixCursor.RowBuilder mRowBuilder = matrixCursor.newRow();
                        mRowBuilder.add("key", values[index]);
                        mRowBuilder.add("value", values[index + 1]);
                    }
                }
            }
        }
        catch (Exception exception) {
            Log.e(TAG, exception.toString());
        }
        return matrixCursor;
    }

    @Override
    public boolean onCreate() {
        TelephonyManager telManager = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portString = telManager.getLine1Number().substring(telManager.getLine1Number().length() - 4);
        final String portNumber = String.valueOf((Integer.parseInt(portString)) * 2);

        CURRENT_PORT = portString;
        ring.nodeID = portString;
        ring.successor = portString;
        ring.predecessor = portString;

        try{

            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
            MAXIMUM_HASH = genHash("5554");

            if(!portNumber.equals("11108")){
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "11108", CURRENT_PORT);
            }
        } catch (Exception exception){
            Log.e(TAG, exception.getMessage());
        }
        return true;
    }

    private class ServerTask extends AsyncTask<ServerSocket, String, Void>{

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];
            try{
                while(true){

                    Socket client = serverSocket.accept();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
                    PrintWriter write = new PrintWriter(client.getOutputStream(), true);
                    String msg;

                    if((msg = reader.readLine()) != null) {
                        if (PORTS.contains(msg) && msg.length() == 4) {
                            if (FLAG && ring.nodeID.equals("5554")) {
                                ring.successor = msg;
                                ring.predecessor = msg;
                                write.println("PRADEEP6" + ":" + ring.nodeID + ":" + ring.nodeID);
                            } else {
                                Ring insertLoc = ring.findBackNode(msg);
                                write.println("PRADEEP6" + ":" + insertLoc.nodeID + ":" + insertLoc.successor);
                            }
                            MAXIMUM_HASH = genHash(msg).compareTo(MAXIMUM_HASH) > 0 ? genHash(msg) : MAXIMUM_HASH;

                            FLAG = false;
                        } else if (msg.contains("Data_Node")) {
                            write.println("Node_Data" + ":" + ring.nodeID + ":" + ring.predecessor + ":" + ring.successor);
                        } else if(msg.contains("PRADEEP1")) {
                            write.println("DELETED" + ":" + String.valueOf(delete(mUri, msg.split(":")[1], null)));
                        } else if(msg.contains("PRADEEP2")) {
                            ContentValues mContentValues = new ContentValues();
                            mContentValues.put("key", msg.split(":")[1]);
                            mContentValues.put("value", msg.split(":")[2]);

                            insert(mUri, mContentValues);
                        } else if(msg.contains("PRADEEP3")){
                            MatrixCursor localCursor = (MatrixCursor) query(mUri, null, msg.split(":")[1], null, null);

                            String response = "";
                            int first = localCursor.getColumnIndex("key");
                            int second = localCursor.getColumnIndex("value");
                            localCursor.moveToFirst();
                            if (localCursor.getCount() > 0) {
                                do {
                                    response = response + localCursor.getString(first) + ":" + localCursor.getString(second) + ":";
                                } while (localCursor.moveToNext());

                                localCursor.close();
                                if (response.length() > 0) {
                                    response = response.substring(0, response.length() - 1);
                                }
                            }

                            write.println("QUERY-"+response);
                        } else {
                            if (msg.contains("PRADEEP4")) {
                                ring.successor = msg.split(":")[1];
                            } else {
                                ring.predecessor = msg.split(":")[1];
                            }
                            write.println("UPDATED");
                        }
                    }
                }
            } catch (IOException ioException){
                Log.e(TAG, ioException.getMessage());
            } catch (Exception exception){
                Log.e(TAG, exception.getMessage());
            }
            return null;
        }

        @Override
        protected void onProgressUpdate(String... values) {
        }

        @Override
        protected void onPostExecute(Void aVoid) {
        }
    }

    private class ClientTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... params) {
            try {
                Socket client = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(params[0]));

                PrintWriter writer = new PrintWriter(client.getOutputStream(), true);
                BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
                writer.println(params[1]);

                while (!client.isClosed()) {
                    String ack = reader.readLine();

                    if (ack.contains("PRADEEP6")) {
                        String[] contents = ack.split(":");

                        ring.predecessor = contents[1];
                        ring.successor = contents[2];
                    }
                    client.close();
                }

                client = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(ring.predecessor) * 2);

                writer = new PrintWriter(client.getOutputStream(), true);
                reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
                writer.println("PRADEEP4:"+CURRENT_PORT);

                while (!client.isClosed()) {
                    String ack = reader.readLine();
                    if(ack.equals("UPDATED")){
                        client.close();
                    }
                }

                client = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(ring.successor) * 2);

                writer = new PrintWriter(client.getOutputStream(), true);
                reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
                writer.println("PRADEEP5:"+CURRENT_PORT);

                while (!client.isClosed()) {
                    String ack = reader.readLine();
                    if (ack.equals("UPDATED")) {
                        client.close();
                    }
                }
            } catch (Exception exception) {
                Log.e(TAG, exception.getMessage());
            }
            return null;
        }
    }

    private Uri buildUri(String scheme, String authority) {
        Uri.Builder uriBuilder = new Uri.Builder();
        uriBuilder.authority(authority);
        uriBuilder.scheme(scheme);
        return uriBuilder.build();
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }
}