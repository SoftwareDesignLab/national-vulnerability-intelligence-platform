package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.Product;
import edu.rit.se.nvip.productnameextractor.CpeLookUp;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AffectedReleaseLoaderTest {

	@Test
	public void getProductFromCpeTest() {
		CpeLookUp loader = CpeLookUp.getInstance();
		Product p = loader.productFromCpe("cpe:2.3:a:vmware:vcenter_server:5.0:*:*:*:*:*:*:*");

		assertTrue(p.getDomain().contains("VMware vCenter Server 5.0"));
	}

	@Test
	public void productListFromDomainTest() {
		CpeLookUp loader = CpeLookUp.getInstance();
		List<String> products = loader.productListFromDomain("Microsoft Word 2003");

		assertTrue(products.size() > 0);
	}

}
