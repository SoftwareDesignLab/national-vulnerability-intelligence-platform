package edu.rit.se.nvip.mitre.capec;

public class CapecRelationship {

    private final String nature;
    private final CapecType type;
    private final String capecID;
    private final String capecName;

    public CapecRelationship(String nature, String type, String id, String name) {
        this.nature = nature;
        switch(type) {
            case "Meta Attack Pattern":
                this.type = CapecType.META;
                break;
            case "Detailed Attack Pattern":
                this.type = CapecType.DETAILED;
                break;
            case "Standard Attack Pattern":
            default:
                this.type = CapecType.STANDARD;
        }
        this.capecID = id;
        this.capecName = name;
    }

    public String getNature() { return nature; }

    public CapecType getType() { return type; }

    public String getCapecID() { return capecID; }

    public String getCapecName() { return capecName; }
}
