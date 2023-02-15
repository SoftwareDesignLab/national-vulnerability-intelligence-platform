-- MySQL dump 10.13  Distrib 8.0.20, for Win64 (x86_64)
--
-- Host: localhost    Database: nvip
-- ------------------------------------------------------
-- Server version	8.0.20

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


--
-- Create the database
--
CREATE DATABASE IF NOT EXISTS nvip
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;

USE nvip;

-- Needed for parallel db processes
SET GLOBAL max_connections = 600;
-- Disable Group By requirement for aggregations
SET GLOBAL sql_mode="STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION";

--
-- Table structure for table `affectedrelease`
--

DROP TABLE IF EXISTS `affectedrelease`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `affectedrelease` (
  `Id` int NOT NULL AUTO_INCREMENT,
  `cve_id` varchar(20) NOT NULL,
  `product_id` int NOT NULL,
  `release_date` datetime DEFAULT NULL,
  `version` tinytext,
  PRIMARY KEY (`Id`),
  KEY `AffectedRelease_Index_ProductId` (`product_id`),
  KEY `AffectedRelease_Index_CveId` (`cve_id`),
  CONSTRAINT `affectedrelease_cve_id_fk` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`),
  CONSTRAINT `affectedrelease_product_id_fk` FOREIGN KEY (`product_id`) REFERENCES `product` (`product_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6202 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cvssscore`
--

DROP TABLE IF EXISTS `cvssscore`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cvssscore` (
  `cve_id` varchar(20) DEFAULT NULL,
  `cvss_severity_id` int DEFAULT NULL,
  `severity_confidence` double DEFAULT NULL,
  `impact_score` text,
  `impact_confidence` double DEFAULT NULL,
  KEY `CveId` (`cve_id`),
  CONSTRAINT `cvssscore_cve_id_fk` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cvssseverity`
--

DROP TABLE IF EXISTS `cvssseverity`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cvssseverity` (
  `cvss_severity_id` int NOT NULL AUTO_INCREMENT,
  `cvss_severity_class` varchar(45) NOT NULL,
  PRIMARY KEY (`cvss_severity_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dailyrunhistory`
--

DROP TABLE IF EXISTS `dailyrunhistory`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dailyrunhistory` (
  `run_id` int NOT NULL AUTO_INCREMENT,
  `run_date_time` datetime NOT NULL,
  `crawl_time_min` double DEFAULT NULL,
  `db_time_min` double DEFAULT NULL,
  `total_cve_count` int DEFAULT NULL,
  `not_in_nvd_count` int DEFAULT NULL,
  `not_in_mitre_count` int DEFAULT NULL,
  `not_in_both_count` int DEFAULT NULL,
  `new_cve_count` int DEFAULT NULL,
  `avg_time_gap_nvd` double DEFAULT NULL,
  `avg_time_gap_mitre` double DEFAULT NULL,
  `added_cve_count` int DEFAULT NULL,
  `updated_cve_count` int DEFAULT NULL,
  PRIMARY KEY (`run_id`),
  KEY `DailyRunHistory_Index_date` (`run_date_time`)
) ENGINE=InnoDB AUTO_INCREMENT=1080 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `exploit`
--

DROP TABLE IF EXISTS `exploit`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `exploit` (
  `exploit_id` int NOT NULL AUTO_INCREMENT,
  `vuln_id` int NOT NULL,
  `cve_id` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `publisher_id` int DEFAULT NULL,
  `publish_date` datetime DEFAULT NULL,
  `publisher_url` tinytext CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `exploit_code` text,
  `nvip_record_date` datetime NOT NULL,
  PRIMARY KEY (`exploit_id`),
  KEY `exploit_vuln_id_fk_idx` (`vuln_id`),
  CONSTRAINT `exploit_vuln_id_fk` FOREIGN KEY (`vuln_id`) REFERENCES `vulnerability` (`vuln_id`)
) ENGINE=InnoDB AUTO_INCREMENT=39441 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `nvipsourceurl`
--

DROP TABLE IF EXISTS `nvipsourceurl`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `nvipsourceurl` (
  `source_id` int NOT NULL AUTO_INCREMENT,
  `url` varchar(500) DEFAULT NULL,
  `description` text,
  `http_status` int DEFAULT '200',
  PRIMARY KEY (`source_id`),
  KEY `NvipSourceUrl_Index_Url` (`url`)
) ENGINE=InnoDB AUTO_INCREMENT=296430 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `permission`
--

DROP TABLE IF EXISTS `permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission` (
  `permission_id` int NOT NULL AUTO_INCREMENT,
  `permission_name` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`permission_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `product`
--

DROP TABLE IF EXISTS `product`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `product` (
  `product_id` int NOT NULL AUTO_INCREMENT,
  `cpe` varchar(300) DEFAULT NULL,
  `domain` text,
  PRIMARY KEY (`product_id`),
  KEY `Product_Index_Cpe` (`cpe`)
) ENGINE=InnoDB AUTO_INCREMENT=73881 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `role`
--

DROP TABLE IF EXISTS `role`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `role` (
  `role_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(20) NOT NULL,
  PRIMARY KEY (`role_id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

INSERT INTO role (role_id, name) VALUES (1, 'admin');
INSERT INTO role (role_id, name) VALUES (2, 'user');

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user` (
  `user_id` int NOT NULL AUTO_INCREMENT,
  `user_name` varchar(45) NOT NULL,
  `password_hash` varchar(1024) NOT NULL,
  `token` varchar(512) DEFAULT NULL,
  `token_expiration_date` datetime DEFAULT NULL,
  `first_name` varchar(50) DEFAULT NULL,
  `last_name` varchar(50) DEFAULT NULL,
  `role_id` int NOT NULL,
  `email` varchar(45) DEFAULT NULL,
  `registered_date` datetime DEFAULT NULL,
  `last_login_date` datetime DEFAULT NULL,
  PRIMARY KEY (`user_id`),
  KEY `user_name_idx` (`user_name`),
  KEY `user_role_idx` (`role_id`),
  CONSTRAINT `user_role` FOREIGN KEY (`role_id`) REFERENCES `role` (`role_id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `userpermission`
--

DROP TABLE IF EXISTS `userpermission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `userpermission` (
  `user_id` int NOT NULL,
  `permission_id` int NOT NULL,
  `date` datetime DEFAULT NULL,
  PRIMARY KEY (`user_id`,`permission_id`),
  KEY `userpermission_permission_id_fk_idx` (`permission_id`),
  CONSTRAINT `userpermission_permission_id_fk` FOREIGN KEY (`permission_id`) REFERENCES `permission` (`permission_id`),
  CONSTRAINT `userpermission_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `uservulnerabilityupdate`
--

DROP TABLE IF EXISTS `uservulnerabilityupdate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `uservulnerabilityupdate` (
  `update_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `cve_id` varchar(20) NOT NULL,
  `datetime` datetime NOT NULL,
  `info` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`update_id`),
  KEY `idx_user_id` (`user_id`),
  CONSTRAINT `fk_user_id` FOREIGN KEY (`user_id`) REFERENCES `user` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=36 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vdocharacteristic`
--

DROP TABLE IF EXISTS `vdocharacteristic`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vdocharacteristic` (
  `cve_id` varchar(20) NOT NULL,
  `vdo_label_id` int DEFAULT NULL,
  `vdo_confidence` double DEFAULT NULL,
  `vdo_noun_group_id` int DEFAULT NULL,
  KEY `CveId` (`cve_id`),
  KEY `vdo_noun_group` (`vdo_noun_group_id`),
  KEY `vdo_label` (`vdo_label_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vdolabel`
--

DROP TABLE IF EXISTS `vdolabel`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vdolabel` (
  `vdo_label_id` int NOT NULL AUTO_INCREMENT,
  `vdo_label_name` varchar(100) NOT NULL,
  `vdo_label_for_ui` varchar(100) DEFAULT NULL,
  `vdo_noun_group_id` int DEFAULT NULL,
  PRIMARY KEY (`vdo_label_id`),
  KEY `vdolabel_vdo_noun_group_id_idx` (`vdo_noun_group_id`),
  CONSTRAINT `vdolabel_vdo_noun_group_id` FOREIGN KEY (`vdo_noun_group_id`) REFERENCES `vdonoungroup` (`vdo_noun_group_id`)
) ENGINE=InnoDB AUTO_INCREMENT=28 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vdonoungroup`
--

DROP TABLE IF EXISTS `vdonoungroup`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vdonoungroup` (
  `vdo_noun_group_id` int NOT NULL AUTO_INCREMENT,
  `vdo_noun_group_name` varchar(100) NOT NULL,
  `vdo_name_for_ui` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`vdo_noun_group_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vulnerability`
--

DROP TABLE IF EXISTS `vulnerability`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vulnerability` (
  `vuln_id` int NOT NULL AUTO_INCREMENT,
  `cve_id` varchar(20) DEFAULT NULL,
  `description` mediumtext,
  `platform` text,
  `introduced_date` datetime DEFAULT NULL,
  `published_date` datetime DEFAULT NULL,
  `created_date` datetime DEFAULT NULL,
  `last_modified_date` datetime DEFAULT NULL,
  `fixed_date` date DEFAULT NULL,
  `exists_at_mitre` int DEFAULT NULL,
  `exists_at_nvd` int DEFAULT NULL,
  `time_gap_nvd` int DEFAULT NULL,
  `time_gap_mitre` int DEFAULT NULL,
  `status_id` int DEFAULT '1',
  PRIMARY KEY (`vuln_id`),
  UNIQUE KEY `vuln_id_UNIQUE` (`vuln_id`),
  KEY `Vulnerability_Index_CveId` (`cve_id`),
  KEY `status_id_idx` (`status_id`),
  CONSTRAINT `status_id` FOREIGN KEY (`status_id`) REFERENCES `vulnerabilitystatus` (`status_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2157992 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vulnerabilityaggregate`
--

DROP TABLE IF EXISTS `vulnerabilityaggregate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vulnerabilityaggregate` (
  `vuln_id` int NOT NULL,
  `cve_id` varchar(20) NOT NULL,
  `description` mediumtext NOT NULL,
  `platform` text,
  `published_date` datetime DEFAULT NULL,
  `last_modified_date` datetime DEFAULT NULL,
  `fixed_date` datetime DEFAULT NULL,
  `exists_at_nvd` int DEFAULT NULL,
  `exists_at_mitre` int DEFAULT NULL,
  `vdo_labels` text,
  `vdo_label_confidences` text,
  `vdo_noun_groups` text,
  `urls` text,
  `base_severities` text,
  `severity_confidences` text,
  `impact_scores` text,
  `impact_confidences` text,
  `product_id` text,
  `cpe` text,
  `domain` text,
  `version` text,
  `exploit_publish_date` datetime DEFAULT NULL,
  `exploit_url` varchar(200) DEFAULT NULL,
  `run_date_time` datetime DEFAULT NULL,
  KEY `fk_vuln_id_vulnerability_idx` (`vuln_id`),
  KEY `fk_cve_id_vulnerability_idx` (`cve_id`),
  KEY `idx_datetime` (`run_date_time`),
  CONSTRAINT `fk_cve_id_vulnerability` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`),
  CONSTRAINT `fk_vuln_id_vulnerability` FOREIGN KEY (`vuln_id`) REFERENCES `vulnerability` (`vuln_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vulnerabilitystatus`
--

DROP TABLE IF EXISTS `vulnerabilitystatus`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vulnerabilitystatus` (
  `status_id` int NOT NULL AUTO_INCREMENT,
  `status_label` varchar(45) NOT NULL,
  PRIMARY KEY (`status_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vulnerabilityupdate`
--

DROP TABLE IF EXISTS `vulnerabilityupdate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vulnerabilityupdate` (
  `update_id` int NOT NULL AUTO_INCREMENT,
  `vuln_id` int NOT NULL,
  `column_name` varchar(45) NOT NULL,
  `column_value` mediumtext,
  `run_id` int NOT NULL,
  PRIMARY KEY (`update_id`),
  KEY `vuln_id_fk_idx` (`vuln_id`),
  KEY `run_id_fk_idx` (`run_id`),
  CONSTRAINT `run_id_fk` FOREIGN KEY (`run_id`) REFERENCES `dailyrunhistory` (`run_id`),
  CONSTRAINT `vuln_id_fk` FOREIGN KEY (`vuln_id`) REFERENCES `vulnerability` (`vuln_id`)
) ENGINE=InnoDB AUTO_INCREMENT=420186 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vulnsourceurl`
--

DROP TABLE IF EXISTS `vulnsourceurl`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vulnsourceurl` (
  `id` int NOT NULL AUTO_INCREMENT,
  `cve_id` varchar(20) NOT NULL,
  `url` varchar(300) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `VulnSource_Url_Index` (`url`),
  KEY `Vulnsource_CveId_Index` (`cve_id`),
  CONSTRAINT `vulnsourceurl_cve_id_fk` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`)
) ENGINE=InnoDB AUTO_INCREMENT=422199 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping events for database 'nvip'
--

--
-- Dumping routines for database 'nvip'
--
/*!50003 DROP FUNCTION IF EXISTS `getAvgCvesAdded` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!50003 DROP FUNCTION IF EXISTS `getAvgCvesUpdated` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!50003 DROP FUNCTION IF EXISTS `getAvgTimeGapNvd` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!50003 DROP FUNCTION IF EXISTS `getTotalVulnerabilityCount` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!50003 DROP PROCEDURE IF EXISTS `getMainPageCounts` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!50003 DROP PROCEDURE IF EXISTS `getSearchFormInfo` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;;
CREATE DEFINER=`root`@`localhost` PROCEDURE `getSearchFormInfo`()
BEGIN
	DECLARE cvss_scores VARCHAR(50) DEFAULT NULL; 
    DECLARE vdo_noun_groups VARCHAR(3000) DEFAULT NULL;
    
    SELECT group_concat(cs.cvss_severity_class SEPARATOR ";") INTO cvss_scores 
    FROM (SELECT cvss_severity_class FROM cvssseverity WHERE cvss_severity_class != "n/a" GROUP BY cvss_severity_class ORDER BY cvss_severity_class ASC) cs;
    
	SELECT group_concat(vdo.vdo_labels SEPARATOR "|") AS vdo_noun_groups INTO vdo_noun_groups FROM 
    (SELECT CONCAT(vn.vdo_name_for_ui, ":", group_concat(vl.vdo_label_for_ui SEPARATOR ";")) AS vdo_labels FROM 
    (SELECT vdo_noun_group_id, vdo_label_id FROM vdocharacteristic GROUP BY vdo_noun_group_id, vdo_label_id) vc
	INNER JOIN vdonoungroup vn
	ON vn.vdo_noun_group_id = vc.vdo_noun_group_id
	INNER JOIN vdolabel vl
	ON vl.vdo_label_id = vc.vdo_label_id
	GROUP BY vc.vdo_noun_group_id) vdo;
    
    SELECT cvss_scores, vdo_noun_groups FROM vulnerability LIMIT 1;
END ;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!50003 DROP PROCEDURE IF EXISTS `getVulnerabilitiesByCriteria` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;;
CREATE DEFINER=`root`@`localhost` PROCEDURE `getVulnerabilitiesByCriteria`(IN vuln_id INTEGER, IN keyword VARCHAR(1000), IN start_date TIMESTAMP, IN end_date TIMESTAMP, 
IN cvss_scores VARCHAR(50), IN vdo_noun_groups VARCHAR(1500), IN vdo_labels VARCHAR(1500), IN in_mitre VARCHAR(1), IN in_nvd VARCHAR(1),
IN limit_count INTEGER, IN is_before TINYINT(1))
BEGIN
	DROP TEMPORARY TABLE IF EXISTS tmp_vuln_criteria;
    SET SESSION group_concat_max_len = 50000;
    
	SET @vuln_id = vuln_id;
    SET @keyword = keyword;
	SET @start_date = start_date; 
	SET @end_date = end_date;
	SET @cvss_scores = cvss_scores; 
    SET @vdo_noun_groups = vdo_noun_groups;
    SET @vdo_labels = vdo_labels;
	SET @limit_count = limit_count;
    SET @is_before = is_before;
    SET @vuln_count = 0;

	IF in_mitre IS NULL THEN
		SET @in_mitre = NULL;
    ELSE
		SET @in_mitre = CAST(in_mitre AS UNSIGNED INTEGER);
    END IF;
    
    IF in_nvd IS NULL THEN
		SET @in_nvd = NULL;
    ELSE
		SET @in_nvd = CAST(in_nvd AS UNSIGNED INTEGER);
    END IF;

	SET @q_return = 'SELECT';

	SET @q = '';
    
    SET @q_where_clause = '';

	-- JOIN VulnerabilityUpdate and DailyRunHistory tables
	SET @q_return = CONCAT(@q_return, ' ', 'vu.run_date_time', ',');
	SET @q = CONCAT(@q, ' ', 'INNER JOIN', ' ', '(SELECT vu.vuln_id, MAX(drh.run_id) AS "run_id", MAX(drh.run_date_time) AS "run_date_time" 
	FROM dailyrunhistory drh INNER JOIN vulnerabilityupdate vu ON vu.run_id = drh.run_id');
        
	IF (@start_date IS NULL AND @end_date IS NULL) THEN
		SET @q = CONCAT(@q, ' ', 'WHERE ? IS NULL AND ? IS NULL GROUP BY vu.vuln_id) vu', ' ', 'ON vu.vuln_id = v.vuln_id');
	ELSEIF @start_date IS NULL THEN
		SET @q = CONCAT(@q, ' ', 'WHERE (? IS NULL NULL AND drh.run_date_time <= ?) GROUP BY vu.vuln_id) vu', ' ', 'ON vu.vuln_id = v.vuln_id');
	ELSEIF @end_date IS NULL THEN 
		SET @q = CONCAT(@q, ' ', 'WHERE (drh.run_date_time >= ? AND ? IS NULL) GROUP BY vu.vuln_id) vu', ' ', 'ON vu.vuln_id = v.vuln_id');
	ELSE 
		SET @q = CONCAT(@q, ' ', 'WHERE drh.run_date_time BETWEEN ? AND ? GROUP BY vu.vuln_id) vu', ' ', 'ON vu.vuln_id = v.vuln_id');
	END IF;

	-- JOIN AffectedRelease and Product tables
    SET @q_return = CONCAT(@q_return, ' ', 'p.product_ids, p.cpe_list, p.domains, p.versions', ',');
    SET @q = CONCAT(@q, ' ', 'LEFT JOIN', ' ', '(SELECT ar.cve_id, group_concat(ar.version SEPARATOR ";") AS versions, 
    group_concat(p.product_id SEPARATOR ";") AS product_ids, group_concat(p.cpe SEPARATOR ";") AS cpe_list, 
    group_concat(p.domain SEPARATOR ";") AS domains FROM affectedrelease ar INNER JOIN product p ON ar.product_id = p.product_id',
    ' ', 'GROUP BY ar.cve_id) p ON p.cve_id = v.cve_id');
    
    -- JOIN CVSSScore table
    SET @q_return = CONCAT(@q_return, ' ', 'cs.base_severities, cs.severity_confidences, cs.impact_scores, cs.impact_confidences', ',');
	SET @q = CONCAT(@q, ' ', 'INNER JOIN', ' ', '(SELECT csc.cve_id, group_concat(cse.cvss_severity_class SEPARATOR ";") AS base_severities, group_concat(csc.severity_confidence SEPARATOR ";") 
AS severity_confidences, group_concat(csc.impact_score SEPARATOR ";") AS impact_scores, group_concat(csc.impact_confidence SEPARATOR ";") AS impact_confidences',
	' ', 'FROM cvssscore csc INNER JOIN cvssseverity cse ON cse.cvss_severity_id = csc.cvss_severity_id');
    
	IF @cvss_scores IS NULL THEN
		SET @q = CONCAT(@q, ' ', 'WHERE ? IS NULL GROUP BY csc.cve_id) cs', ' ', 'ON cs.cve_id = v.cve_id');
	ELSE 
		SET @q = CONCAT(@q, ' ', 'WHERE FIND_IN_SET(cse.cvss_severity_class, ?) > 0 GROUP BY csc.cve_id) cs', ' ', 'ON cs.cve_id = v.cve_id');
	END IF;
    
    -- JOIN VulnerabilityCharacteristic table
	SET @q_return = CONCAT(@q_return, ' ', 'vc.vdo_labels, vc.vdo_label_confidences, vc.vdo_noun_groups', ',');
    SET @q = CONCAT(@q, ' ', 'INNER JOIN', ' ', '(SELECT vc.cve_id, group_concat(vl.vdo_label_name SEPARATOR ";") AS vdo_labels, group_concat(vc.vdo_confidence SEPARATOR ";") AS vdo_label_confidences, 
group_concat(ifnull(vn.vdo_noun_group_name, "None") SEPARATOR ";") AS vdo_noun_groups FROM vdocharacteristic vc', 
	' ', 'INNER JOIN vdonoungroup vn ON vn.vdo_noun_group_id = vc.vdo_noun_group_id', ' ',
	'INNER JOIN vdolabel vl ON vl.vdo_label_id = vc.vdo_label_id');
    
    IF @vdo_noun_groups IS NULL THEN
		SET @q = CONCAT(@q, ' ', 'WHERE ? IS NULL');
    ELSE
		SET @q = CONCAT(@q, ' ', 'WHERE FIND_IN_SET(vn.vdo_noun_group_name, ?) > 0');
    END IF;

	IF @vdo_labels IS NULL THEN
		SET @q = CONCAT(@q, ' ', 'AND ? IS NULL GROUP BY vc.cve_id) vc', ' ', 'ON vc.cve_id = v.cve_id');
    ELSE
		SET @q = CONCAT(@q, ' ', 'AND FIND_IN_SET(vl.vdo_label_name, ?) > 0 GROUP BY vc.cve_id) vc', ' ', 
        'ON vc.cve_id = v.cve_id');
    END IF;

	-- Keyword check
    IF @keyword IS NULL THEN
        SET @q_where_clause = CONCAT(@q_where_clause, ' ', 'AND ? IS NULL');
    ELSE
		IF LOCATE("CVE-", @keyword) > 0 THEN
			SET @q_where_clause = CONCAT(@q_where_clause, ' ', 'AND v.cve_id=?');
        ELSE 
			SET @q_where_clause = CONCAT(@q_where_clause, ' ', 'AND LOCATE(?, v.description) > 0');
		END IF;
    END IF;

	-- In Site check (i.e. NVD, MITRE)
    IF @in_mitre IS NULL THEN
		SET @q_where_clause = CONCAT(@q_where_clause, ' ', 'AND ? IS NULL');
    ELSE
		SET @q_where_clause = CONCAT(@q_where_clause, ' ', 'AND v.exists_at_mitre = ?');
    END IF;
    
    IF @in_nvd IS NULL THEN
		SET @q_where_clause = CONCAT(@q_where_clause, ' ', 'AND ? IS NULL');
    ELSE
		SET @q_where_clause = CONCAT(@q_where_clause, ' ', 'AND v.exists_at_nvd = ?');
    END IF;

	-- Add the FROM statement for the query. Add the LIMIT statement to the end of the query
	IF @q = '' THEN    
		SET @q = ' FROM vulnerability v';
	ELSE
		SET @q = CONCAT('FROM vulnerability v', ' ', @q);
	END IF;
    
    -- Check if getting vulnerabilities before/after the given vuln id
    IF @is_before = 1 THEN
		SET @q_where_clause = CONCAT('WHERE v.vuln_id < ?', ' ', @q_where_clause);
    ELSE
		SET @q_where_clause = CONCAT('WHERE v.vuln_id > ?', ' ', @q_where_clause);
    END IF;

	-- Add the Vulnerability returns
	SET @q_return = CONCAT(@q_return, ' ', 'v.vuln_id, v.cve_id, v.description, v.platform, v.published_date, v.last_modified_date, 
    v.fixed_date, v.exists_at_nvd, v.exists_at_mitre');

	SET @q = CONCAT('CREATE TEMPORARY TABLE tmp_vuln_criteria', ' ', @q_return, ' ', @q, ' ', @q_where_clause, ' ', 
    'ORDER BY v.vuln_id DESC LIMIT 10000');

	-- SELECT @q FROM Vulnerability LIMIT 1;

	PREPARE stmt FROM @q;

	EXECUTE stmt USING @start_date, @end_date, @cvss_scores, @vdo_noun_groups, @vdo_labels, @vuln_id, @keyword, @in_mitre, @in_nvd;
    
    -- Get the total count of CVEs from the temporary table
	SELECT COUNT(vuln_id) INTO @vuln_count FROM tmp_vuln_criteria;

	SELECT *, @vuln_count AS total_count FROM tmp_vuln_criteria LIMIT limit_count;
    
	DROP TEMPORARY TABLE IF EXISTS tmp_vuln_criteria;
END ;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!50003 DROP PROCEDURE IF EXISTS `getVulnerability` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!50003 DROP PROCEDURE IF EXISTS `login` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!50003 DROP PROCEDURE IF EXISTS `prepareDailyVulnerabilities` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;;
CREATE DEFINER=`root`@`localhost` PROCEDURE `prepareDailyVulnerabilities`(IN start_date TIMESTAMP, IN end_date TIMESTAMP, OUT cveCount int)
BEGIN
SET session group_concat_max_len=100000;
DELETE FROM vulnerabilityaggregate;
INSERT INTO vulnerabilityaggregate(SELECT v.vuln_id, v.cve_id, v.description, v.platform, v.published_date, v.last_modified_date, v.fixed_date, v.exists_at_nvd, v.exists_at_mitre, vc.vdo_labels, 
	vc.vdo_label_confidences, vc.vdo_noun_groups, vsu.urls, cs.base_severities, cs.severity_confidences, cs.impact_scores, cs.impact_confidences, vap.product_id, vap.cpe, 
    vap.domain, vap.version, expl.publish_date, expl.publisher_url, vu.run_date_time 
	FROM (SELECT vu.vuln_id, MAX(drh.run_id) AS "run_id", MAX(drh.run_date_time) AS "run_date_time" FROM dailyrunhistory drh
	INNER JOIN vulnerabilityupdate vu ON vu.run_id = drh.run_id 
	WHERE drh.run_date_time BETWEEN start_date AND end_date GROUP BY vu.vuln_id) vu
	INNER JOIN vulnerability v 
	ON v.vuln_id = vu.vuln_id
	LEFT JOIN (SELECT vc.cve_id, group_concat(vl.vdo_label_name SEPARATOR ";") AS vdo_labels, group_concat(vc.vdo_confidence SEPARATOR ";") AS vdo_label_confidences, 
group_concat(ifnull(vn.vdo_noun_group_name, "None") SEPARATOR ";") AS vdo_noun_groups FROM vdocharacteristic vc 
	INNER JOIN vdonoungroup vn ON vn.vdo_noun_group_id = vc.vdo_noun_group_id
	INNER JOIN vdolabel vl ON vl.vdo_label_id = vc.vdo_label_id GROUP BY vc.cve_id) vc 
	ON vc.cve_id = v.cve_id 
	LEFT JOIN (SELECT cve_id, group_concat(url SEPARATOR ";") AS urls FROM vulnsourceurl GROUP BY cve_id) vsu 
	ON vsu.cve_id = v.cve_id 
	LEFT JOIN (SELECT csc.cve_id, group_concat(cse.cvss_severity_class SEPARATOR ";") AS base_severities, group_concat(csc.severity_confidence SEPARATOR ";") 
	AS severity_confidences, group_concat(csc.impact_score SEPARATOR ";") AS impact_scores, group_concat(csc.impact_confidence SEPARATOR ";")  AS impact_confidences 
	FROM cvssscore csc INNER JOIN cvssseverity cse ON cse.cvss_severity_id = csc.cvss_severity_id GROUP BY csc.cve_id) cs 
	ON cs.cve_id = v.cve_id 
    LEFT JOIN (SELECT cve_id, group_concat(ar.product_id SEPARATOR ";") AS product_id, group_concat(cpe SEPARATOR ";") AS cpe, group_concat(domain SEPARATOR ";") AS domain, group_concat(version SEPARATOR ";") AS version FROM affectedrelease ar
	INNER JOIN product p ON p.product_id = ar.product_id GROUP BY cve_id) vap
    ON vap.cve_id = v.cve_id
    LEFT JOIN exploit as expl on expl.vuln_id = v.vuln_id
    WHERE v.status_id <> 2 and v.description is not null ORDER BY v.vuln_id desc);

-- Remove certain CVEs
DELETE FROM nvip.vulnerabilityaggregate WHERE description like '%** RESERVED ** This candidate%' or description like '%** REJECT ** DO NOT USE%';
DELETE FROM nvip.vulnerabilityaggregate WHERE length(description) < 50; 
SELECT count(*) INTO cveCount FROM vulnerabilityaggregate;
END ;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2021-08-16 15:59:22

-- MySQL dump 10.13  Distrib 8.0.20, for Win64 (x86_64)
--
-- Host: localhost    Database: nvip
-- ------------------------------------------------------
-- Server version	8.0.20

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Dumping data for table `vdolabel`
--

LOCK TABLES `vdolabel` WRITE;
/*!40000 ALTER TABLE `vdolabel` DISABLE KEYS */;
INSERT INTO `vdolabel` VALUES (1,'Trust Failure','Trust Failure',1),(2,'Man-in-the-Middle','Man-in-the-Middle',1),(3,'Channel','Channel',2),(4,'Authentication Bypass','Authentication Bypass',1),(5,'Physical Hardware','Physical Hardware',2),(6,'Application','Application',2),(7,'Host OS','Host OS',2),(8,'Firmware','Firmware',2),(9,'Code Execution','Code Execution',1),(10,'Context Escape','Context Escape',1),(11,'Guest OS','Guest OS',2),(12,'Hypervisor','Hypervisor',2),(13,'Sandboxed','Sandboxed',3),(14,'Physical Security','Physical Security',3),(15,'ASLR','ASLR',3),(16,'Limited Rmt','Limited Rmt',4),(17,'Local','Local',4),(18,'Read','Read',5),(19,'Resource Removal','Resource Removal',5),(20,'HPKP/HSTS','HPKP/HSTS',3),(21,'MultiFactor Authentication','MultiFactor Authentication',3),(22,'Remote','Remote',4),(23,'Write','Write',5),(24,'Indirect Disclosure','Indirect Disclosure',5),(25,'Service Interrupt','Service Interrupt',5),(26,'Privilege Escalation','Privilege Escalation',5),(27,'Physical','Physical',4);
/*!40000 ALTER TABLE `vdolabel` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `vdonoungroup`
--

LOCK TABLES `vdonoungroup` WRITE;
/*!40000 ALTER TABLE `vdonoungroup` DISABLE KEYS */;
INSERT INTO `vdonoungroup` VALUES (1,'ImpactMethod','Impact Method'),(2,'Context','Context'),(3,'Mitigation','Mitigation'),(4,'AttackTheater','Attack Theater'),(5,'LogicalImpact','Logical Impact');
/*!40000 ALTER TABLE `vdonoungroup` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `vulnerabilitystatus`
--

LOCK TABLES `vulnerabilitystatus` WRITE;
/*!40000 ALTER TABLE `vulnerabilitystatus` DISABLE KEYS */;
INSERT INTO `vulnerabilitystatus` VALUES (1,'Crawled'),(2,'Rejected'),(3,'Under Review'),(4,'Accepted');
/*!40000 ALTER TABLE `vulnerabilitystatus` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2021-08-20  8:19:31

-- MySQL dump 10.13  Distrib 8.0.20, for Win64 (x86_64)
--
-- Host: localhost    Database: nvip
-- ------------------------------------------------------
-- Server version	8.0.20

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Dumping data for table `cvssseverity`
--

LOCK TABLES `cvssseverity` WRITE;
/*!40000 ALTER TABLE `cvssseverity` DISABLE KEYS */;
INSERT INTO `cvssseverity` VALUES (1,'HIGH'),(2,'MEDIUM'),(3,'n/a'),(4,'CRITICAL'),(5,'LOW');
/*!40000 ALTER TABLE `cvssseverity` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

DROP TABLE IF EXISTS cvestatuschange;

CREATE TABLE `cvestatuschange` (
  `cve_status_change_id` int NOT NULL AUTO_INCREMENT,
  `vuln_id` int NOT NULL,
  `cve_id` varchar(20) DEFAULT NULL,
  `cpmpared_against` varchar(10) NOT NULL COMMENT 'NVD or MITRE?',
  `old_status_code` tinyint NOT NULL,
  `new_status_code` tinyint NOT NULL,
  `cve_description` mediumtext NOT NULL,
  `time_gap_recorded` tinyint NOT NULL,
  `time_gap_hours` int NOT NULL,
  `status_date` datetime NOT NULL,
  `cve_create_date` datetime NOT NULL,
  PRIMARY KEY (`cve_status_change_id`),
  KEY `fk_cve_id_idx` (`cve_id`),
  CONSTRAINT `fk_cve_id` FOREIGN KEY (`cve_id`) REFERENCES `vulnerability` (`cve_id`)
) ENGINE=InnoDB AUTO_INCREMENT=43254 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

DROP TABLE IF EXISTS patchsourceurl;
DROP TABLE IF EXISTS patchcommit;

CREATE TABLE `patchsourceurl` (
    `source_url_id` int NOT NULL AUTO_INCREMENT,
    `source_url` varchar(500) NULL,
    `vuln_id` int NOT NULL,
    PRIMARY KEY (`source_url_id`),
    UNIQUE INDEX `source_url_id_UNIQUE` (`source_url_id` ASC) VISIBLE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


CREATE TABLE `patchcommit` (
    `source_id` INT NOT NULL,
    `commit_url` VARCHAR(500) NOT NULL,
    `commit_date` DATETIME NULL,
    `commit_message` VARCHAR(500) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
