app.directive('dailyVulnDropdown', ['VDO_NOUN_GROUPS', function(VDO_NOUN_GROUPS) {
	 return {
		 link: function (scope, elem, attrs) {
			scope.confidenceThreshold = 0.3, 
			scope.VDO_NOUN_GROUPS = VDO_NOUN_GROUPS,
			scope.displayProductName = function(productName){
		    	if(productName == null)
		    		return "Impact ";
		    	else if (productName.length > 43)
		    		return productName.substring(0, 44);
		    	else
		    		return productName
		    },
		    scope.displayVulnDescButton = function(vulnContent){
		    	var description = vulnContent.getElementsByClassName("nvip-vuln-desc")[0];
		    	var vulnDescButton = vulnContent.getElementsByClassName("nvip-daily-vuln-desc-toggle")[0];

		    	var descriptionHeight = description.clientHeight;
		    	var maxDescHeight = getComputedStyle(document.documentElement).getPropertyValue('--max-vuln-desc-height-px').replace('px', '');

		    	if (description.style.maxHeight != '') {
		    		// Work-around for when the click event does not activate on each click. Prevents the 
		    		// full description from being shown because it was previously set to the maximum
		    	}
		    	else if (descriptionHeight >= (maxDescHeight*1.2)) {
		    		description.style.maxHeight = getComputedStyle(document.documentElement).getPropertyValue('--max-vuln-desc-height-em');
		    		description.style.overflow = 'hidden';
		    		vulnDescButton.style.display = 'block';
		    	}
		    	else {
		    		description.style.maxHeight = '';
		    		//description.style.overflow = 'visible';
		    		vulnDescButton.style.display = 'none';
		    	}
		    },
			scope.getLabelClass = function(vdo) {
				var confidence = vdo.vdoConfidence;
				
				if (confidence >= 0.65) {
					return "vuln-vdo-label vdo-high-confidence";
				}
				else if (confidence >= 0.3) {
					return "vuln-vdo-label vdo-med-confidence";
				}
				else if (confidence > -1) {
					return "vuln-vdo-label vdo-low-confidence";
				} else {
					return "vuln-vdo-label";
				}
			},
			scope.getVdoLabelsByNounGroup = function(vuln, nounGroup){
		    	var vdoList = vuln.vdoList;
		    	var newVdoList = [];
		    	
		    	angular.forEach(vdoList, function(vdo, key) {
		    		if(vdo.vdoNounGroup == nounGroup){
		    			newVdoList.push(vdo);
		    		}
		    	});
		    	
		    	if(newVdoList.length == 0)
		    		return [];
		    	
		    	return newVdoList;
		    },
		    scope.getVdoLabelsByNounGroup = function(vuln, nounGroup){
		    	var vdoList = vuln.vdoList;
		    	var vdo = null;
		    	var vdoLabels = [];
		    	
		    	angular.forEach(vdoList, function(value, key) {
		    		vdo = value;
		    		if(vdo.vdoNounGroup == nounGroup){
		    			vdoLabels.push(vdo.vdoLabel);
		    		}
		    	});
		    	
		    	if(vdoLabels.length == 0)
		    		return "Unknown";
		    	
		    	return vdoLabels;
		    },
			scope.getVdoList = function(vuln, nounGroup) {
				// TODO: Refactor, will possibly load multiple times
				var vdoList = vuln.vdoList;
				var newVdoList = [];
				
				
				
				//if (vdoList.length == 0) {
				//	newVdoList.push({cveId: " ", vdoLabel: "N/A", vdoConfidence: -1.0, vdoNounGroup: "NA"});
				//} else {
					angular.forEach(vdoList, function(vdo, i) {
						if (vdo.vdoNounGroup == nounGroup) {
							if (vdo.vdoConfidence >= scope.confidenceThreshold) {
								newVdoList.push(vdo);
							}
						}
					});
				//}
				
				/*
				 * var vdoLabelRow = dailyVulnPanel.getElementsByClassName("daily-vuln-dropdown-row-2")[vulnIndex];
    	
			    	if(vdoLabelRow.children.length == 1){
			    		vdoLabel = document.createElement("SPAN");
			    		vdoLabel.innerText = "Unknown";
			    		vdoLabel.classList.add("vuln-vdo-label");
			    		vdoLabelRow.appendChild(vdoLabel);
			    	};
				 */
				
				return newVdoList;
			},
			scope.hasMitigation = function(vuln){
		    	var vdoLabels = scope.getVdoLabelsByNounGroup(vuln, VDO_NOUN_GROUPS.MITIGATION);
		    	
		    	if(vdoLabels == "Unknown")
		    		return false;
		    	else
		    		return true;
		    },
		    scope.isFixed = function(vuln){
		    	if(vuln.fixedDate != null){
		    		return true;
		    	}
		    	
		    	return false;
		    },
		    scope.selectDailyCve = function(event) { 
			
				      
		        // Call for the ancestor since it doesn't sometimes calls the button's children
		        var vulnButton = getAncestor(event.srcElement, "daily-vuln-dropdown-button");
		        var vulnContent = null;
		        var activeButtons = document.getElementsByClassName("daily-vuln-active");
		        var isActive = vulnButton.classList.contains("daily-vuln-active");

		        // Remove all the styling from the existing active buttons
		        angular.forEach(activeButtons, function(activeButton, i){
		    		vulnContent = getSiblingByClassName(activeButton, "daily-vuln-content");
		    		activeButton.classList.remove("daily-vuln-active");
	                vulnContent.style.maxHeight = 0;
					activeButton.getElementsByClassName("description-text")[0].style.color = "rgba(64, 64, 64, 0.7)";
		        })
		        
				vulnButton.getElementsByClassName("description-text")[0].style.color = "rgba(64, 64, 64, 0.7)";

		        // Check if the button was previously active. Will not add the active class back to it
		        if (!isActive){
			        // Set the called button to the active button now that all the previous ones were closed
		    		vulnContent = getSiblingByClassName(vulnButton, "daily-vuln-content");
					
					vulnButton.getElementsByClassName("description-text")[0].style.color = "black";

		    		vulnButton.classList.add("daily-vuln-active");
			        vulnContent.style.maxHeight = '500px';
			        scope.displayVulnDescButton(vulnContent);
		        }
		    },
			scope.vulnDescToggle = function(ele){
		    	var button = ele.srcElement;
		    	var vulnContent = getAncestor(ele.target, "daily-vuln-content");
		    	var description = vulnContent.getElementsByClassName("nvip-vuln-desc")[0];
		    	
		    	if(description.style.maxHeight != 'calc(100%)'){
		    		description.style.maxHeight = 'calc(100%)';
		    		description.style.overflow = 'visible';
		    		button.innerText = "Show Less";
		    	}
		    	else {
		    		description.style.maxHeight = getComputedStyle(document.documentElement).getPropertyValue('--max-vuln-desc-height-em');
		    		description.style.overflow = 'hidden';
		    		button.innerText = "Show More";
		    	}
		    }

			scope.isGreyDropDown = function(index) {
				return index % 2 == 1;
			}
			
			scope.getCpes = function(vuln) {
				
				if (vuln.cpes.length == 0) {
					return "N/A";
				}
				
				cpeParse = vuln.cpes[0].split(":");
				return cpeParse[3]+" "+cpeParse[4];
			}
			
		 },
		 restrict: "E",
		 scope: {
			vuln:  '=',
			index: '='
			
		 },
		 template: 
			`
			 	<button type="button" class="daily-vuln-dropdown-button col-12 Index{{index}}" ng-click="selectDailyCve($event)" ng-class="{'grey-dropdown': isGreyDropDown(index)}">
					<div class="daily-vuln-dropdown-row">
						<div class="daily-vuln-dropdown-row-1">
							<span class="nvip-cve-number-span cve_id" ng-bind="vuln.cveId"></span>
							<span class="description-text" ng-bind="vuln.description"></span>
								<span class="daily-vuln-dropdown-icon-box">
									<img class="nvd_logo" ng-class="{true: 'is_present', false: ''}[vuln.existInNvd]" src="images/nvd_logo.svg" aria-hidden="true"/>
									<img class="mitre_logo" ng-class="{true: 'is_present', false: ''}[vuln.existInMitre]"  src="images/mitre_corporation_logo.svg" aria-hidden="true">
									<img class="mitigation_icon" ng-show="hasMitigation(vuln)" src="images/mitigation_shield.svg" aria-hidden="true">
									<img class="is_fixed_logo" ng-show="isFixed(vuln)" src="images/is_fixed_icon.svg" alt="Fixed">
								</span>
								<i class="nvip-vuln-dropdown-caret fa fa-angle-down"></i>
							</div>
							<div class="daily-vuln-dropdown-row-2">
								<span class="daily-vuln-product">Impact :</span>
								&nbsp
								<span class="daily-vuln-product product-items" ng-show="vuln.vdoList.length == 0">N/A</span>
								<span data-ng-repeat="vdo in getVdoList(vuln, VDO_NOUN_GROUPS.LOGICAL_IMPACT) | orderBy: '-map.vdoConfidence' | limitTo: 2" class="{{getLabelClass(vdo)}} daily-vuln-product product-items">
									{{vdo.vdoLabel}}
								</span>
								&nbsp
								<span class="daily-vuln-product">Method :</span>
								<span class="daily-vuln-product product-items" ng-show="vuln.vdoList.length == 0">N/A</span>
								&nbsp
								<span data-ng-repeat="vdo in getVdoList(vuln, VDO_NOUN_GROUPS.IMPACT_METHOD) | orderBy: '-map.vdoConfidence' | limitTo: 2" class="{{getLabelClass(vdo)}} daily-vuln-product product-items">
								 	{{vdo.vdoLabel}}
								</span>
							</div>
						</div>
					</button>
					<div class="daily-vuln-content Content-Index{{index}}">
						<div class="daily-vuln-description">
							<p>Description</p>
							<p class="nvip-vuln-desc" ng-bind="vuln.description.slice(0, 997)+'...'"></p>
						</div>
						<div class="nvip-daily-vuln-desc-toggle">
							<button class="nvip-button" ng-click="vulnDescToggle($event)">Show More</button>
						</div>
						<div class="daily-vuln-info"> 
							<div>
								<p>Impact:</p>
								<span data-ng-repeat="vdo in getVdoList(vuln, VDO_NOUN_GROUPS.LOGICAL_IMPACT) | orderBy: '-map.vdoConfidence' | limitTo: 2" style="margin-left: .5em; font-size: 15px">
									{{vdo.vdoLabel}}
								</span>
							</div>
							<div>
								<p>Method:</p>
								<p ng-bind="vuln.type" style="margin-left: .5em; font-size: 15px"></p>
							</div>
						</div>
					<div class="daily-vuln-detail" ng-controller="SearchController as search">
						<button class="nvip-button nvip-view-info-button" ng-click="storeResults(vuln.vulnId)">
							View Info
						</button>
					</div>
	     `
	 };
}]);