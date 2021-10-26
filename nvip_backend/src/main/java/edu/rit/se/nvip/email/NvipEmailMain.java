package edu.rit.se.nvip.email;

import edu.rit.se.nvip.db.DatabaseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Date;
import java.util.ArrayList;
import java.util.HashMap;

public class NvipEmailMain {

    private static final Logger logger = LogManager.getLogger(NvipEmailMain.class.getSimpleName());
    private static final DatabaseHelper db = DatabaseHelper.getInstance();

    public static void main(String[] args) {
        if (args.length == 0) {
            sendNotificationEmail();
        } else {
            sendNotificationEmail(args[0]);
        }
    }

    public static void sendNotificationEmail() {
        ArrayList<String> emails = db.getEmails();
        HashMap<String, String> newCves = db.getCVEByRunDate(new Date(System.currentTimeMillis()));

        for (String email : emails) {

        }

    }

    public static void sendNotificationEmail(String emailAddress) {

    }

}
