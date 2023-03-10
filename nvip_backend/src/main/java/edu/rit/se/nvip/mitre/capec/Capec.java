package edu.rit.se.nvip.mitre.capec;

import java.util.ArrayList;
import java.util.HashMap;

public class Capec {


    // TODO: we might this in /model, not sure

    // CAPEC Description
    private String description;

    // Likelihood of attack TODO: this and severity might be able to be enumed
    private String likelihood;

    // Typical Severity
    private String severity;

    // Relationships
    //TODO:

    // Execution Flow
    // TODO:

    // Prerequisites
    private ArrayList<String> prereqs;

    // Skills required
    private String skills;

    // Resources required
    private String resources;

    // Consequences
    //TODO:

    // Mitigations
    private String mitigations;

    // Example Instances
    private String examples;

    // Related Weaknesses (CWEs)
    private HashMap<String, String> weaknesses;

    // Taxonomy Mappings
    private HashMap<String, String> tax;

    // References
    private ArrayList<String> refs;

    // Content History
    // TODO:

    /**
     * Common Attack Pattern Enumeration and Classification (CAPEC) model
     * capec.mitre.org
     */
    public Capec() {}
}
