package edu.rit.se.nvip.mitre.capec;
import java.util.ArrayList;
import java.util.HashMap;

public class Capec {

    // Attack Pattern ID
    private final String id;

    // CAPEC Abstraction
    private final CapecType abstraction;

    // CAPEC Description
    private final String description;

    // Likelihood of attack
    private final String likelihood;

    // Typical Severity
    private final String severity;

    /**
     * This table shows the other attack patterns and high level categories that are related
     * to this attack pattern. These relationships are defined as ChildOf and ParentOf, and
     * give insight to similar items that may exist at higher and lower levels of abstraction.
     * In addition, relationships such as CanFollow, PeerOf, and CanAlsoBe are defined to show
     * similar attack patterns that the user may want to explore
     */
    private final ArrayList<CapecRelationship> relationships;

    // Prerequisites
    private final ArrayList<String> prereqs;

    // Skills required
    private final ArrayList<String> skills;

    // Resources required
    private final String resources;

    /**
     * This table specifies different individual consequences associated with the attack pattern.
     * The Scope identifies the security property that is violated, while the Impact describes
     * the negative technical impact that arises if an adversary succeeds in their attack. The
     * Likelihood provides information about how likely the specific consequence is expected to be
     * seen relative to the other consequences in the list. For example, there may be high likelihood
     * that a pattern will be used to achieve a certain impact, but a low likelihood that it will
     * be exploited to achieve a different impact.
     */
    private final HashMap<String, ArrayList<String>> consequences;

    // Mitigations
    private final String mitigations;

    // Example Instances
    private final String examples;


    /**
     * A Related Weakness relationship associates a weakness with this attack pattern.
     * Each association implies a weakness that must exist for a given attack to be successful.
     * If multiple weaknesses are associated with the attack pattern, then any of the weaknesses
     * (but not necessarily all) may be present for the attack to be successful.
     * Each related weakness is identified by a CWE identifier.
     */
    private final HashMap<String, String> weaknesses;

    /**
     * CAPEC mappings to ATT&CK techniques leverage an inheritance model to streamline
     * and minimize direct CAPEC/ATT&CK mappings. Inheritance of a mapping is indicated
     * by text stating that the parent CAPEC has relevant ATT&CK mappings. Note that the
     * ATT&CK Enterprise Framework does not use an inheritance model as part of the mapping to CAPEC
     */
    private final HashMap<String, String> tax;

    /**
     * Common Attack Pattern Enumeration and Classification (CAPEC) model
     * capec.mitre.org
     * This class encapsulates 1 of 559 CAPEC Attack Patterns
     */
    public Capec(
            String id,
            CapecType abstraction,
            String description,
            String likelihood,
            String severity,
            ArrayList<CapecRelationship> relationships,
            ArrayList<String> prereqs,
            ArrayList<String> skills,
            String resources,
            HashMap<String, ArrayList<String>> consequences,
            String mitigations,
            String examples,
            HashMap<String, String> weaknesses,
            HashMap<String, String> tax) {
        this.id = id;
        this.abstraction = abstraction;
        this.description = description;
        this.likelihood = likelihood;
        this.severity = severity;
        this.relationships = relationships;
        this.prereqs = prereqs;
        this.skills = skills;
        this.resources = resources;
        this.consequences = consequences;
        this.mitigations = mitigations;
        this.examples = examples;
        this.weaknesses = weaknesses;
        this.tax = tax;
    }

    public String getId() { return id; }

    public CapecType getAbstraction() { return abstraction; }

    public String getDescription() { return description; }

    public String getLikelihood() { return likelihood; }

    public String getSeverity() { return severity; }

    public ArrayList<CapecRelationship> getRelationships() {
        return relationships;
    }

    public ArrayList<String> getPrereqs() {
        return prereqs;
    }

    public ArrayList<String> getSkills() {
        return skills;
    }

    public String getExamples() { return examples; }

    public HashMap<String, ArrayList<String>> getConsequences() {
        return consequences;
    }

    public String getMitigations() {
        return mitigations;
    }

    public String getResources() {
        return resources;
    }

    public HashMap<String, String> getWeaknesses() {
        return weaknesses;
    }

    public HashMap<String, String> getTax() {
        return tax;
    }

}
