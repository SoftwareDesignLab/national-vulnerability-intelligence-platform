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
 * THE SOFTWARE IS PROVIDED �AS IS�, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package servlet;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Properties;

import static org.mockito.Mockito.*;

public class MainServletTest {

    @Test
    public void testDoGet() {
        Properties props = new Properties();
        try {
            props.load(new FileReader("../nvip_backend/src/main/resources/db-mysql.properties"));
        } catch (IOException e) {
            System.out.println("Cannot find db-mysql.properties file in backend resources!");
            System.exit(1);
        }

        String dbUser = props.getProperty("dataSource.user");
        String dbPass = props.getProperty("dataSource.password");

        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter("countGraphs")).thenReturn("all");


        PrintWriter writerMock = mock(PrintWriter.class);
        try {
            when(response.getWriter()).thenReturn(writerMock);
        } catch (IOException e) {
            System.out.println("IO Exception: " + e.getMessage());
        }

        MainServlet mainServlet = new MainServlet();

        //Note database username/password must be set in dbUser and dbPass
        System.setProperty("JDBC_CONNECTION_STRING", "jdbc:mysql://" + dbUser + ":" + dbPass + "@localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true");

        try {
            mainServlet.handleRequest(request, response);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        assertEquals(0, response.getStatus());
        verify(writerMock).write(anyString());
    }

    @Test
    public void testDoGetNoParams() {
        Properties props = new Properties();
        try {
            props.load(new FileReader("../nvip_backend/src/main/resources/db-mysql.properties"));
        } catch (IOException e) {
            System.out.println("Cannot find db-mysql.properties file in backend resources!");
            System.exit(1);
        }

        String dbUser = props.getProperty("dataSource.user");
        String dbPass = props.getProperty("dataSource.password");

        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter("countGraphs")).thenReturn(null);


        PrintWriter writerMock = mock(PrintWriter.class);
        try {
            when(response.getWriter()).thenReturn(writerMock);
        } catch (IOException e) {
            System.out.println("IO Exception: " + e.getMessage());
        }

        MainServlet mainServlet = new MainServlet();

        //Note database username/password must be set in dbUser and dbPass
        System.setProperty("JDBC_CONNECTION_STRING", "jdbc:mysql://" + dbUser + ":" + dbPass + "@localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true");

        try {
            mainServlet.handleRequest(request, response);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        assertEquals(0, response.getStatus());
        verify(writerMock).write(anyString());
    }

}