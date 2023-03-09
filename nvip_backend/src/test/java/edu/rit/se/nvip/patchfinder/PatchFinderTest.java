package edu.rit.se.nvip.patchfinder;

import edu.rit.se.nvip.db.DatabaseHelper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class PatchFinderTest {

    @Mock
    private DatabaseHelper dbh;

    @Test
    public void parseURLByCVETest() {
        try (MockedStatic<DatabaseHelper> databaseStaticMock = Mockito.mockStatic(DatabaseHelper.class)) {
            // don't use a real database
            databaseStaticMock.when(DatabaseHelper::getInstance).thenReturn(dbh);
            Map<String, ArrayList<String>> cpeRetVal = new HashMap<>();
            cpeRetVal.put("cpe:foo:bar:foobar:barfoo", new ArrayList<>(Arrays.asList("vuln_id", "cve_id")));
            when(dbh.getCPEsByCVE("cve_id")).thenReturn(cpeRetVal);
            PatchFinder pf = new PatchFinder();
            // just make sure no errors happen
            pf.parseURLByCVE("cve_id");
        } catch (Exception e) {e.printStackTrace(); fail();}
    }

    @Test
    public void parseURLByProductIdTest() {
        try (MockedStatic<DatabaseHelper> databaseStaticMock = Mockito.mockStatic(DatabaseHelper.class)) {
            databaseStaticMock.when(DatabaseHelper::getInstance).thenReturn(dbh);
            Map<String, ArrayList<String>> cpeRetVal = new HashMap<>();
            cpeRetVal.put("cpe:foo:bar:foobar:barfoo", new ArrayList<>(Arrays.asList("vuln_id", "cve_id")));
            when(dbh.getCPEById(11111)).thenReturn(cpeRetVal);
            PatchFinder pf = new PatchFinder();
            pf.parseURLByProductId(11111);
        } catch (Exception e) {e.printStackTrace(); fail();}
    }
}
