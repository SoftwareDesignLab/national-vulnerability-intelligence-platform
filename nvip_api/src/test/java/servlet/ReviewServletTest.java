/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the �Software�), to deal
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
package servlet;

import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Properties;

import static org.junit.Assert.assertEquals;

import static org.mockito.Mockito.*;

public class ReviewServletTest{

    @Test
    public void testDoGetUnauthorizedUser() {
        Properties props = new Properties();
        try {
            props.load(new FileReader("../nvip_backend/src/main/resources/db-mysql.properties"));
        } catch (IOException e) {
            System.out.println("Cannot find db-mysql.properties file in backend resources!");
            System.exit(1);
        }

        String dbUser = props.getProperty("dataSource.user");
        String dbPass = props.getProperty("dataSource.password");

        System.setProperty("JDBC_CONNECTION_STRING", "jdbc:mysql://" + dbUser + ":" + dbPass + "@localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true");

        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        when(req.getParameter("username")).thenReturn("testUsername");
        when(req.getParameter("token")).thenReturn(null);

        //Setup mock writer for response
        PrintWriter printMock = mock(PrintWriter.class);
        try {
            when(resp.getWriter()).thenReturn(printMock);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        ReviewServlet reviewServlet = new ReviewServlet();
        try {
            reviewServlet.doGet(req, resp);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        verify(resp, times(2)).setStatus(401);
        verify(printMock).write("Unauthorized user!");
        verify(printMock).write("Unauthorized user by id get!");
    }

    @Test
    public void testDoGetWithCveId() {
        //TODO: Update request with parameters for successful CVE ID extraction
        //TODO: Find expected data pulled from DB given CVE ID
        Properties props = new Properties();
        try {
            props.load(new FileReader("../nvip_backend/src/main/resources/db-mysql.properties"));
        } catch (IOException e) {
            System.out.println("Cannot find db-mysql.properties file in backend resources!");
            System.exit(1);
        }

        String dbUser = props.getProperty("dataSource.user");
        String dbPass = props.getProperty("dataSource.password");

        System.setProperty("JDBC_CONNECTION_STRING", "jdbc:mysql://" + dbUser + ":" + dbPass + "@localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true");

        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        when(req.getParameter("username")).thenReturn("testUsername");
        when(req.getParameter("token")).thenReturn("2");
        when(req.getParameter("cveID")).thenReturn("CVE-2021-22317");

        //Setup mock writer for response
        PrintWriter printMock = mock(PrintWriter.class);
        try {
            when(resp.getWriter()).thenReturn(printMock);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        ReviewServlet reviewServlet = new ReviewServlet();
        try {
            reviewServlet.doGet(req, resp);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        verify(printMock).write("{\n" +
                "  \"vuln_id\": \"2409866\",\n" +
                "  \"cve_id\": \"CVE-2021-22317\",\n" +
                "  \"description\": \"\\\"There is an Information Disclosure vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may impair data confidentiality.\\\"\",\n" +
                "  \"status_id\": \"1\",\n" +
                "  \"run_date_time\": \"2023-02-03 18:38:49\",\n" +
                "  \"vdoGroups\": {\n" +
                "    \"null\": {\n" +
                "      \"vdoLabel\": {}\n" +
                "    }\n" +
                "  },\n" +
                "  \"vulnDomain\": []\n" +
                "}");
        assertEquals(0, resp.getStatus());
        verifyNoMoreInteractions(resp);
    }
}