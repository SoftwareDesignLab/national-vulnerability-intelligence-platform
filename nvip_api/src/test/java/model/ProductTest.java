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