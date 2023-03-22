/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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