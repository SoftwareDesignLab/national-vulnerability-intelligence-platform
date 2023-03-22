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