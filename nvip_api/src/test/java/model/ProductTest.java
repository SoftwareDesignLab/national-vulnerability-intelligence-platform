package model;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ProductTest{

    @Test
    public void testGetDomain() {
        Product product = new Product(12345, "testCpe", "testDomain", "testRelease", "testVersion");
        assertEquals("testDomain", product.getDomain());
    }

    @Test
    public void testGetCpe() {
        Product product = new Product(12345, "testCpe", "testDomain", "testRelease", "testVersion");
        assertEquals("testCpe", product.getCpe());
    }

    @Test
    public void testGetProductId() {
        Product product = new Product(12345, "testCpe", "testDomain", "testRelease", "testVersion");
        assertEquals(12345, product.getProductId(), 0);
    }

    @Test
    public void testSetProductId() {
        Product product = new Product(12345, "testCpe", "testDomain", "testRelease", "testVersion");
        product.setProductId(54321);
        assertEquals(54321, product.getProductId(), 0);
    }

    @Test
    public void testGetReleaseDate() {
        Product product = new Product(12345, "testCpe", "testDomain", "testRelease", "testVersion");
        assertEquals("testRelease", product.getReleaseDate());
    }

    @Test
    public void testSetReleaseDate() {
        Product product = new Product(12345, "testCpe", "testDomain", "testRelease", "testVersion");
        product.setReleaseDate("testSetRelease");
        assertEquals("testSetRelease", product.getReleaseDate());
    }

    @Test
    public void testGetVersion() {
        Product product = new Product(12345, "testCpe", "testDomain", "testRelease", "testVersion");
        assertEquals("testVersion", product.getVersion());
    }

    @Test
    public void testSetVersion() {
        Product product = new Product(12345, "testCpe", "testDomain", "testRelease", "testVersion");
        product.setVersion("testSetVersion");
        assertEquals("testSetVersion", product.getVersion());
    }
}