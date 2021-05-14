/**
 * 
 */
app.directive('nvipVulnFilter', function() {
	 return {
		 link: function (scope, elem, attrs) {
			 scope.filterVulns = function(vulnSearch){
				    console.log("filterVulns");
				    console.log(vulnSearch);
				    var cve = null;
				    var cveDropdowns = null;
				        
				    if (vulnSearch.length >= 3) {
				    	console.log(document.getElementsByClassName("daily-vuln-dropdown-button"));
				    	//console.log(searchResults);
				     }
				     else {
				    	
				     }
			}
				 /**
				  * Set the width of the sidebar to 250px and the left margin of the page
				  * content to 250px
				 **/
				 scope.toggleFilter = function() {
					console.log("Toggle Filter");
				    var filterCtn =  document.getElementsByClassName("nvip-vuln-filter-ctn")[0];
				    	
				    if (filterCtn.classList.contains("active")) {
				    	filterCtn.classList.remove("active");
				    	filterCtn.style.width = "1.5em";
				    }
				    else {
				    	filterCtn.classList.add("active");
				    	filterCtn.style.width = "31.5em";
				    }
				 }	 
		 },
		 restrict: "E",
		 scope: {
			 searchResults: '='
		 },
		 template: 
		 `<div class="nvip-vuln-filter-ctn">
			<div class="daily-cve-filter-content">
			  	<div class="daily-cve-search-container col-11">
			  		<i class="daily-vuln-search-icon fa fa-search" aria-hidden="true"></i>
					<input class="daily-cve-search-bar col-10" type="text" ng-model="vulnSearch" ng-blur="searchFocusOut()" placeholder="Filter vulnerabilities"
						ng-keyup="filterVulns(vulnSearch)" />
					<i class="daily-vuln-search-cancel-icon fa fa-times-circle" aria-hidden="true"></i>
				</div>
				<div class="nvip-form-dropdown-field col-12" ng-click="toggleContent($event)">
					<div class="nvip-form-dropdown-left col-11">
						<label>VDO</label>
					</div>
					<div class="nvip-form-dropdown-right col-1">
						<i class="nvip-form-dropdown-caret fa fa-angle-left" aria-hidden="true"></i>
					</div>
				</div>
				<div class="nvip-form-dropdown-content col-11">
				</div>
				<div class="daily-cve-filter-btns">
					<div class="daily-vuln-filter-btn">
						<span>Product</span>
						<i class="fa fa-angle-right fa-2x" aria-hidden="true"></i>	
					</div>
					<div class="daily-vuln-filter-btn">
						<span>VDO</span>
						<i class="fa fa-angle-right fa-2x" aria-hidden="true"></i>	
					</div>
					<div class="daily-vuln-filter-btn">
						<span>CVSS Score</span>
						<i class="fa fa-angle-right fa-2x" aria-hidden="true"></i>	
					</div>
					<div class="daily-vuln-filter-btn">
						<span>Status</span>
						<i class="fa fa-angle-right fa-2x" aria-hidden="true"></i>	
					</div>
					<div class="daily-vuln-filter-btn">
						<span>In MITRE/NVD</span>
						<i class="fa fa-angle-right fa-2x" aria-hidden="true"></i>	
					</div>
				</div>
			</div>
		  <button class="daily-cve-filter-btn" type="button" ng-click="toggleFilter()">
		  	<i class="fa fa-angle-right fa-2x" aria-hidden="true"></i>
		  </button>
		</div>`
	 };
});