/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
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
package edu.rit.se.nvip.model;

/**
 * 
 * @author axoeec
 *
 */
public class DailyRun {
	int runId = 0;
	String runDateTime;
	float crawlTimeMin;
	int totalCveCount;
	int notInNvdCount;
	int notInMitreCount;
	int notInBothCount;
	int newCveCount;
	int droppedFromListCount;
	double avgTimeGapNvd = 0;
	double avgTimeGapMitre = 0;
	double databaseTimeMin;

	int addedCveCount = 0;
	int updatedCveCount = 0;

	public DailyRun(String runDateTime, float crawlTimeMin, int totalCveCount, int notInNvdCount, int notInMitreCount, int notInBothCount, int newCveCount, float avgTimeGapNvd,
			float avgTimeGapMitre) {
		this.runDateTime = runDateTime;
		this.crawlTimeMin = crawlTimeMin;
		this.totalCveCount = totalCveCount;
		this.notInNvdCount = notInNvdCount;
		this.notInMitreCount = notInMitreCount;
		this.notInBothCount = notInBothCount;
		this.newCveCount = newCveCount;
		this.avgTimeGapNvd = avgTimeGapNvd;
		this.avgTimeGapMitre = avgTimeGapMitre;
	}

	public DailyRun() {

	}

	public String getRunDateTime() {
		return runDateTime;
	}

	public float getCrawlTimeMin() {
		return crawlTimeMin;
	}

	public int getTotalCveCount() {
		return totalCveCount;
	}

	public int getNotInNvdCount() {
		return notInNvdCount;
	}

	public int getNotInMitreCount() {
		return notInMitreCount;
	}

	public int getNotInBothCount() {
		return notInBothCount;
	}

	public int getNewCveCount() {
		return newCveCount;
	}

	public double getAvgTimeGapNvd() {
		return avgTimeGapNvd;
	}

	public double getAvgTimeGapMitre() {
		return avgTimeGapMitre;
	}

	public void setRunDateTime(String runDateTime) {
		this.runDateTime = runDateTime;
	}

	public void setCrawlTimeMin(float crawlTimeMin) {
		this.crawlTimeMin = crawlTimeMin;
	}

	public void setTotalCveCount(int totalCveCount) {
		this.totalCveCount = totalCveCount;
	}

	public void setNotInNvdCount(int notInNvdCount) {
		this.notInNvdCount = notInNvdCount;
	}

	public void setNotInMitreCount(int notInMitreCount) {
		this.notInMitreCount = notInMitreCount;
	}

	public void setNotInBothCount(int notInBothCount) {
		this.notInBothCount = notInBothCount;
	}

	public void setNewCveCount(int newCveCount) {
		this.newCveCount = newCveCount;
	}

	public void setAvgTimeGapNvd(double avgTimeGapNvd) {
		this.avgTimeGapNvd = avgTimeGapNvd;
	}

	public void setAvgTimeGapMitre(double avgTimeGapMitre) {
		this.avgTimeGapMitre = avgTimeGapMitre;
	}

	public int getDroppedFromListCount() {
		return droppedFromListCount;
	}

	public void setDroppedFromListCount(int droppedFromListCount) {
		this.droppedFromListCount = droppedFromListCount;
	}

	public double getDatabaseTimeMin() {
		return databaseTimeMin;
	}

	public void setDatabaseTimeMin(double databaseTimeMin) {
		this.databaseTimeMin = databaseTimeMin;
	}

	public int getRunId() {
		return runId;
	}

	public void setRunId(int runId) {
		this.runId = runId;
	}

	public int getAddedCveCount() {
		return addedCveCount;
	}

	public void setAddedCveCount(int addedCveCount) {
		this.addedCveCount = addedCveCount;
	}

	public int getUpdatedCveCount() {
		return updatedCveCount;
	}

	public void setUpdatedCveCount(int updatedCveCount) {
		this.updatedCveCount = updatedCveCount;
	}
	
	

}
