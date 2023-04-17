package edu.rit.se.nvip.cveprocess;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;


public class CveProcessorTest {

    private final String CVE_ID = "CVE-1999-0001";

    private CveProcessor cveProcessor = new CveProcessor(new HashSet<>(), new HashSet<>());
    private Map<String, CompositeVulnerability> foundVulnerabilities = new HashMap<>();

    @BeforeEach public void addFoundVulnerability(){
        foundVulnerabilities.put(CVE_ID, new CompositeVulnerability(0, CVE_ID));
    }

    @AfterEach void clearFoundVulnerability(){
        foundVulnerabilities.clear();
    }

    @Test
    public void vulnerabilityNotInMitreWhenNoMitreCves(){

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityNotInNvdWhenNoNvdCves(){

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityInNvdWhenIdMatches(){
        Set<String> cves = new HashSet<>();
        cves.add(CVE_ID);

        cveProcessor = new CveProcessor(cves, new HashSet<>());

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities);

        assertEquals(0, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityInMitreWhenIdMatches(){
        Set<String> cves = new HashSet<>();
        cves.add(CVE_ID);

        cveProcessor = new CveProcessor(new HashSet<>(), cves);

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(0, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityInBothWhenIdMatches(){
        Set<String> cves = new HashSet<>();
        cves.add(CVE_ID);

        cveProcessor = new CveProcessor(cves, cves);

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities);

        assertEquals(0, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(0, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }

    @Test
    public void vulnerabilityInBothWhenFoundNewDescriptionForReserved() {
        foundVulnerabilities.get(CVE_ID).setFoundNewDescriptionForReservedCve(true);

        Set<String> cves = new HashSet<>();
        cves.add(CVE_ID);

        cveProcessor = new CveProcessor(cves, cves);

        HashMap<String, List<Object>> processedCves = cveProcessor.checkAgainstNvdMitre(foundVulnerabilities);

        assertEquals(1, processedCves.get(CveProcessor.NVD_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.NVD_MITRE_CVE_KEY).size());
        assertEquals(1, processedCves.get(CveProcessor.ALL_CVE_KEY).size());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getNvdStatus());
        assertEquals(1, foundVulnerabilities.get(CVE_ID).getMitreStatus());
    }
}
