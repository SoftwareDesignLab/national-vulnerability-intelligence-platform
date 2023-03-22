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
