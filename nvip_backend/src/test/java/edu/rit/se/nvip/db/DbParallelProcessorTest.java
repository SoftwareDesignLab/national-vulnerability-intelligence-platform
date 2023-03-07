package edu.rit.se.nvip.db;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.Invocation;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class DbParallelProcessorTest {

    @Mock
    private DatabaseHelper dbh;

    @Test
    public void executeInParallelTest() {
        try (MockedStatic<DatabaseHelper> mockStaticDB = Mockito.mockStatic(DatabaseHelper.class)) {
            mockStaticDB.when(DatabaseHelper::getInstanceForMultiThreading).thenReturn(dbh);
            when(dbh.getConnectionStatus()).thenReturn("connstatus");
            when(dbh.recordVulnerabilityList(any(), anyInt())).thenReturn(true);
            List<CompositeVulnerability> vulns = new ArrayList<>();
            for (int i = 0; i < 5000; i++) {
                vulns.add(new CompositeVulnerability(i, "source", "cve", "platform", "pubdate", "moddate", "description", "domain"));
            }
            DbParallelProcessor dbpp = new DbParallelProcessor();
            dbpp.executeInParallel(vulns, 10101);
            Collection<Invocation> invocations = Mockito.mockingDetails(dbh).getInvocations();
            boolean hasShutdown = false;
            boolean hasInsert = false;
            for (Invocation inv : invocations) {
                if (inv.toString().equals("dbh.shutdown();")) {
                    hasShutdown = true;
                }
                if (inv.toString().contains("dbh.recordVulnerabilityList(")) {
                    hasInsert = true;
                }
            }
            assertTrue(hasShutdown && hasInsert);
        } catch (Exception e) {e.printStackTrace(); fail();}
    }
}