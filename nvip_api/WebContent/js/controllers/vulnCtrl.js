/**
 * 
 */

angular.module('controllers', []).controller('VulnerabilityController', [ '$scope', '$http', '$routeParams', '$rootScope', function($scope, $rootScope, $http, $routeParams) {
     
    $http.defaults.headers.post["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
    $scope.vulnId = $routeParams.vulnId;
    $scope.vulnSearch = "";

    $scope.init = function (id) {
	    $scope.getDailyVulns();
  	};
    
    $scope.getVulnInfo = function() {
        $http({
            url : 'vulnerabilityServlet',
            method : "GET",  
            params : { vulnId : $scope.vulnId }       
        }).then(function(response) {
			if(response != null) {
                console.log(response)
                $scope.vuln = response.data;
                $scope.fillVulnTabs($scope.vuln);
            } else {
                console.log(response)
                $scope.vuln = null;
            }			
        }, function(response) {
			console.log("Failure -> " + response.data);
            $scope.vuln = null;
        });
    };

    $scope.getDailyVulns = function() {
        $http({
            url : 'vulnerabilityServlet',
            method : "GET",  
            params : {daily: true}       
        }).then(function(response) {
            $scope.dailyVulns = [];
            angular.forEach(response.data.map, function(value, key) {
                $scope.dailyVulns.push(value.myArrayList);
            });
            console.log($scope.dailyVulns);
            $scope.fillDailyVulnBars($scope.dailyVulns);
        }, function(response) {
            console.log("Failure -> " + response.data);
            $scope.dailyVulns = response.data.map;
        });
    };
	
	$scope.searchFocusOut = function(){
        // console.log("Search bar lost focus");
    }
    $scope.searchVulns = function(vulnSearch){
        console.log("Keyup");

        if (vulnSearch.length > 2) {
            $http({
                url : 'vulnerabilityServlet',
                method : "GET",  
                params : {match: "Gentoo"}       
            }).then(function(response) {
                console.log("Ello");
                console.log(response);
            }, function(response) {
                console.log("Failure -> " + response.data);
                $scope.dailyVulns = response.data.map;
            });
        }
    }

    $scope.fillDailyVulnBars = function(dailyVulns) {
    	console.log("fillDailyVulnBars");
    	var cve = null;
        var cveDropdowns = null;
    	var cvePanels = document.getElementsByClassName("daily-cve-panel");
    	
    	for (i = 0; i < cvePanels.length; i++){
        	cveDropdowns = cvePanels[i].getElementsByClassName("daily-vuln-dropdown");
    	}
    }
    
    $scope.fillVulnTabs = function(vuln) {
    	// Severity Tab
    	var cvssScores = vuln.cvssScoreList;
    	var cvssScoreLabels = [["Base", "Impact"]];
    	
    	angular.forEach(cvssScores, function(cvssScore, key) {
    		if (key == 0) {
    			var severityBar = document.getElementsByClassName("vuln-severity-bar")[0];
    			var impactBar = document.getElementsByClassName("vuln-impact-bar")[0];
    			// Determine block height and color based on severity level
    			if (cvssScore.baseSeverity == "CRITICAL") {
    				severityBar.style.height = "22.5em";
    				severityBar.style.backgroundColor = "#000000";
    				severityBar.children[0].innerText = "9.0";
    			}
    			else if (cvssScore.baseSeverity == "HIGH"){
    				severityBar.style.height = "17.5em";
    				severityBar.style.backgroundColor = "#d9534f";
    				severityBar.children[0].innerText = "7.0";
    			}
    			else if (cvssScore.baseSeverity == "MEDIUM") {
    				severityBar.style.height = "12.5em";
    				severityBar.style.backgroundColor = "#f2cc0c";
    				severityBar.children[0].innerText = "5.0";
    			}
    			else if (cvssScore.baseSeverity == "LOW") {
    				severityBar.style.height = "7.5em";
    				severityBar.style.backgroundColor = "#7ebe18";
    				severityBar.children[0].innerText = "3.0";
    			}
    			
    			var impactBarHeight = getBarHeight(cvssScore.impactScore);
    			impactBar.style.height = impactBarHeight + "em";
    			impactBar.children[0].innerText = cvssScore.impactScore;
    			impactBar.style.backgroundColor = "#7ebe18";
    			console.log(impactBarHeight);
    		}
    	});
    	
    	// Characteristics Tabs
    	var vdoList = vuln.vdoList;
    	var vdoGraph = document.getElementsByClassName("vuln-characteristics-graph")[0];
		var vdoBar = null;
    	var vdoBarText = null;
		
    	angular.forEach(vdoList, function(vdo, key) {
    		
    		if (vdo.vdoConfidence > 0.5) {
    			vdoBar = document.createElement("DIV");
    			vdoBar.classList.add("vuln-characteristics-bar");
    			
    			vdoBarText = document.createElement("P");
    			vdoBarText.innerText = vdo.vdoLabel;
    			vdoBar.appendChild(vdoBarText);
    			
    			vdoBarText = document.createElement("P");
    			vdoBarText.innerText = (parseFloat(vdo.vdoConfidence)*100).toFixed(2)+"%";
    			vdoBar.appendChild(vdoBarText);
    			
    			vdoGraph.appendChild(vdoBar);
    		}
    	});
    }
    
    $scope.filterVulns = function(index, vulnSearch, vulnList){
    	console.log("filterVulns");
    	console.log(vulnSearch);
        var cve = null;
        var cveDropdowns = null;
        
        if (vulnSearch.length >= 3) {
        	var cvePanels = document.getElementsByClassName("daily-cve-panel");
        	var visibleCount = 0;
            cveRegex = new RegExp(vulnSearch, "i");
            
            for (i = 0; i < cvePanels.length; i++){
            	cveDropdowns = cvePanels[i].getElementsByClassName("daily-vuln-dropdown");
            	visibleCount = cveDropdowns.length;
            	vulnList = $scope.dailyVulns[i];
            	
            	angular.forEach(vulnList, function(value, key) {
                    cve = value.map;
                    if (cveRegex.test(cve.cveId)) {
                        cveDropdowns[key].style.display = "block";
                    }
                    else if (cveRegex.test(cve.description)) {
                        cveDropdowns[key].style.display = "block";
                    }
                    else if (cveRegex.test(cve.platform)) {
                       cveDropdowns[key].style.display = "block";
                    }
                    else {
                        cveDropdowns[key].style.display = "none";
                        visibleCount--;
                    }
                });
            }
        }
        else {
        	cveDropdowns = document.getElementsByClassName("daily-vuln-dropdown");
        	
        	for (i = 0; i < cveDropdowns.length; i++) {
        		cveDropdowns[i].style.display = "block";
        	}
        }
    }

    function getBarHeight(value) {
    	var barHeight = "2.5";
    	
    	if (isNaN(value))
    		return 0;
    		
    	return barHeight * value;
    }
    
    /*
	 * Set the width of the sidebar to 250px and the left margin of the page
	 * content to 250px
	 */
    $scope.toggleFilter = function() {
    	var filterCtn =  document.getElementsByClassName("daily-cve-filter-container")[0];
    	
    	if (filterCtn.classList.contains("active")) {
    		filterCtn.classList.remove("active");
    		filterCtn.style.width = "1.5em";
    	}
    	else {
    		filterCtn.classList.add("active");
    		filterCtn.style.width = "31.5em";
    	}
    }

	/**
	 * Call the Search controller to retrieve the previous search results 
	 * once the back button is clicked
	 */
	$scope.backToResults = function() {
		console.log("test");
		$rootScope.$emit("RetrieveResults", {});	
	}
	
	
	
	
} ]);