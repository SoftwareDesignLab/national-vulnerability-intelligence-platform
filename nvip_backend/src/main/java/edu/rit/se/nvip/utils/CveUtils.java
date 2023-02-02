package edu.rit.se.nvip.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class CveUtils {
	final static String RESERVED_CVE = "** RESERVED ** This candidate has been reserved";
	final static String REJECTED_CVE = "** REJECT **  DO NOT USE THIS CANDIDATE NUMBER";

	public static boolean isCveReservedEtc(String vulnDescr) {
		return vulnDescr.contains(RESERVED_CVE) || vulnDescr.contains(REJECTED_CVE) || vulnDescr.startsWith("** DISPUTED **");
	}

}
