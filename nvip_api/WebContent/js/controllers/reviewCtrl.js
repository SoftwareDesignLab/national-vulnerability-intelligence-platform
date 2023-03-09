app.controller('ReviewController', [ '$scope', '$timeout', '$rootScope', '$http', '$routeParams', '$cookieStore', function($scope, $timeout, $rootScope, $http, $routeParams, $cookieStore) {
     
    $http.defaults.headers.post["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
    
    $scope.textForDailyUpdateWarning = "You are going to run the procedure to update daily vulnerabilities.\n"+
    										"This procedure aggregates information about CVEs for the last three days.\n"+
    										"Execution of this procedure takes time and has to be initiated only after you finished reviewing CVEs.\n"+
    										"Please, do not initiate this procedure if you are not finished reviewing CVEs.\n"+
    										"Thank you!";
    
    $scope.showForm = true;
        
    $scope.totalCVEs = 0;
    $scope.currentCVE = {};
    $scope.currentCVEnum = 0;
    $scope.currentCVEnumDisplay = 0;
    $scope.currentCVEid = 'CVE-ID HERE';
    
    $scope.vdoUpdates = {
    		update: false,
    		cveID:0,
    		vdoLabels:[]
    };
    
    $scope.cvssFromUI = {
    		cve_id:0,
    		cvss_severity_id:0,
    		severity_confidence:0,
    		impact_score:0,
    		impact_confidence:0
    };
    
    $scope.productsRemove = [];
    
    $scope.review = {};
    $scope.review.currentCVEdesc = "CVE DESCRIPTION IS HERE.";
     
    // Search Result Parameters
    $scope.searchResults = {};
    
    //for pages
    $scope.itemsPerPage = 20;
    $scope.cveToShow = [];
    $scope.currentPage = 0;
    $scope.selectedCVEpage = 0;
    $scope.totalPages = 0;
    $scope.currentIndexInPage=0;
    
    
    $scope.vdoGroupList = ['ImpactMethod', 'Context', 'Mitigation', 'AttackTheater', 'LogicalImpact'];
    $scope.vdoGroupIDs = [];
    $scope.ctxList = ['Hypervisor', 'Firmware', 'Host OS', 'Guest OS', 'Application', 'Channel', 'Physical Hardware'];
    $scope.impctList = ['Context Escape', 'Trust Failure', 'Authentication Bypass', 'Man-in-the-Middle', 'Code Execution'];
    $scope.mitigationList = ['ASLR', 'MultiFactor Authentication', 'Sandboxed', 'HPKP/HSTS', 'Physical Security'];
    $scope.attckThtrList = ['Remote', 'Limited Rmt', 'Local', 'Physical'];
    $scope.lgclImpctList = ['Write', 'Read', 'Resource Removal', 'Service Interrupt', 'Indirect Disclosure', 'Privilege Escalation'];
    
    $scope.cvssClassMap = new Map([
    	['HIGH',1],
    	['MEDIUM',2],
    	['n/a',3],
    	['CRITICAL',4],
    	['LOW',5]
    ]);
       
    //vdoLabel - key, [vdo label id, noun group id]
    $scope.vdoLabels = new Map([
    	["Trust Failure", [1, 1]],
    	["Man-in-the-Middle", [2, 1]],
    	["Channel", [3, 2]],
    	["Authentication Bypass", [4, 1]],
    	["Physical Hardware", [5, 2]],
    	["Application", [6, 2]],
    	["Host OS", [7, 2]],
    	["Firmware", [8, 2]],
    	["Code Execution", [9, 1]],
    	["Context Escape", [10, 1]],
    	["Guest OS", [11, 2]],
    	["Hypervisor", [12, 2]],
    	["Sandboxed", [13, 3]],
    	["Physical Security", [14, 3]],
    	["ASLR", [15, 3]],
    	["Limited Rmt", [16, 4]],
    	["Local", [17, 4]],
    	["Read", [18, 5]],
    	["Resource Removal", [19, 5]],
    	["HPKP/HSTS", [20, 3]],
    	["MultiFactor Authentication", [21, 3]],
    	["Remote", [22, 4]],
    	["Write", [23, 5]],
    	["Indirect Disclosure", [24, 5]],
    	["Service Interrupt", [25, 5]],
    	["Privilege Escalation", [26, 5]],
    	["Physical", [27, 4]]
    ]);
    
    
    $scope.init = function () {
    	$scope.review.curDate = new Date();
    	$scope.review.curDate = formatDate($scope.review.curDate);
    	$scope.review.jumpTo = $scope.currentCVEnumDisplay;
    	
    	var queryString = window.location.hash;
    	queryString = queryString.replace("#/review", "");
    	var urlParams = new URLSearchParams(queryString);
    	var cveIDinURL = urlParams.get('cveid');
		var verdict = urlParams.get('verd');
    	if(cveIDinURL!=null){
    		console.log("CVE ID is " + cveIDinURL);
    		$scope.getCVEdetails(cveIDinURL);
    		if (verdict!=null) {
    			if (verdict == 'accept') {
					$scope.acceptCVE();
				} else if (verdict == 'reject') {
    				$scope.rejectCVE();
				}
			}
    	}
    	else{
    		console.log("CVE ID is absent");
    		$scope.toggleLoading();       	
        	$scope.searchCVEs();
    	}
    	
    	
    	
    	
//    	$scope.testArray.push({name:"one"});
//    	$scope.testArray.push({name:"two"});
//    	$scope.testArray.push({name:"three"});
//    	$scope.testArray.push({name:"four"});
//    	$scope.testArray.push({name:"five"});
    	
    	
    };   
    
    /** Controller Functions **/
    
    $scope.manualCheck = function(item){
    	var state = document.getElementById("ch"+item).checked;
    	if(state){
    		$scope.enableRBgroup(item);
    	}
    	else{
    		$scope.disableRBgroup(item);
    	}
    }
    
    $scope.disableAllRB = function(){
    	$scope.ctxList.forEach($scope.disableRBgroup);
        $scope.impctList.forEach($scope.disableRBgroup);
        $scope.mitigationList.forEach($scope.disableRBgroup);
        $scope.attckThtrList.forEach($scope.disableRBgroup);
        $scope.lgclImpctList.forEach($scope.disableRBgroup);
    	
    }
    
    $scope.enableAllRB = function(){
    	$scope.ctxList.forEach($scope.enableRBgroup);
    	$scope.impctList.forEach($scope.enableRBgroup);
        $scope.mitigationList.forEach($scope.enableRBgroup);
        $scope.attckThtrList.forEach($scope.enableRBgroup);
        $scope.lgclImpctList.forEach($scope.enableRBgroup);
    }
    
    $scope.disableRBgroup = function(rbName) {
    	$scope.disableRB("high"+rbName,true);
    	$scope.disableRB("medium"+rbName,true);
    	$scope.disableRB("low"+rbName,true);
    	$scope.uncheckCB(rbName);
    	document.getElementById("div"+rbName).removeAttribute('class');
    	document.getElementById("div"+rbName).classList.add("review-unchecked-vdo");
    }
    
    $scope.enableRBgroup = function(rbName) {
    	$scope.disableRB("high"+rbName,false);
    	$scope.disableRB("medium"+rbName,false);
    	$scope.disableRB("low"+rbName,false);
    	$scope.check("high"+rbName, true);
    	
    	document.getElementById("div"+rbName).removeAttribute('class');
    	document.getElementById("div"+rbName).classList.add("review-high-confidence");
    }
    
    $scope.enableRBgroup = function(rbName, confidence) {
    	document.getElementById("div"+rbName).removeAttribute('class');
    	$scope.disableRB("high"+rbName,false);
    	$scope.disableRB("medium"+rbName,false);
    	$scope.disableRB("low"+rbName,false);
    	if(confidence<=0.33){
    		$scope.check("low"+rbName, true);
    		document.getElementById("div"+rbName).classList.add("review-low-confidence");
    	}
    	else if(confidence>0.33 && confidence<=0.66){
    		$scope.check("medium"+rbName, true);
    		document.getElementById("div"+rbName).classList.add("review-medium-confidence");
    	}
    	else{
    		$scope.check("high"+rbName, true);
    		document.getElementById("div"+rbName).classList.add("review-high-confidence");
    	}	
    }
    
    $scope.getRBgroupValue = function(rbName){
    	if(!document.getElementById("ch"+rbName).checked)
    		return 0;
    	
    	if(document.getElementById("high"+rbName).checked)
    		return 3;
    	if(document.getElementById("medium"+rbName).checked)
    		return 2;
    	if(document.getElementById("low"+rbName).checked)
    		return 1;
    }
    
    $scope.getVDOconfLabel = function(confidence){
    	if(confidence<=0){
    		return 0;
    	}else if(confidence<=0.33){
    		return 1;
    	}
    	else if(confidence>0.33 && confidence<=0.66){
    		return 2;
    	}
    	else{
    		return 3;
    	}	
    }
    
    $scope.getVDOconfidenceValue = function(confidenceLabel){
    	if(confidenceLabel==0)
    		return 0;
    	if(confidenceLabel==1)
    		return 0.33;
    	if(confidenceLabel==2)
    		return 0.66;
    	if(confidenceLabel==3)
    		return 1;
    }
    
    $scope.compareUIandCVE = function(vdoGroupUI,rbName){

    	var vdoConfidence = $scope.cveDetails.vdoGroups[vdoGroupUI].vdoLabel[rbName];
    	
    	if(vdoConfidence==null)
    		vdoConfidence=0;  	
    	
    	var cveValue = $scope.getVDOconfLabel(vdoConfidence);
    	var uiValue = $scope.getRBgroupValue(rbName);
    	    	
    	if(cveValue==uiValue){
    		$scope.vdoLabels.get(rbName)[2]=false;
    		if (cveValue!=0){
    			var vdoRecord = {
    					labelID: $scope.vdoLabels.get(rbName)[0],
    					confidence: vdoConfidence,
    					groupID: $scope.vdoLabels.get(rbName)[1],
    			};
    			
    			$scope.vdoUpdates.vdoLabels.push(vdoRecord);
    		}
    		
    		return false;
    	}
    	
    	$scope.vdoUpdates.update=true;
    	
    	if (uiValue!=0){
			var vdoRecord = {
					labelID: $scope.vdoLabels.get(rbName)[0],
					confidence: $scope.getVDOconfidenceValue(uiValue),
					groupID: $scope.vdoLabels.get(rbName)[1],
			};
			
			$scope.vdoUpdates.vdoLabels.push(vdoRecord);
		}
    		
//    	$scope.vdoLabels.get(rbName)[2]=true;
//    	console.log("Change in: " + rbName);
    	
    	return true; 
    }
    
    $scope.isChangeInVDO = function(){
    	
    	$scope.vdoUpdates = {
    			update: false,
        		cveID:$scope.cveDetails.cve_id,
        		vdoLabels:[]
        };
    	
    	$scope.ctxList.forEach(function (item, index) {
    		$scope.compareUIandCVE('Context',item);
    	});
    	$scope.impctList.forEach(function (item, index) {
    		$scope.compareUIandCVE('ImpactMethod',item);
    	});
        $scope.mitigationList.forEach(function (item, index) {
    		$scope.compareUIandCVE('Mitigation',item);
    	});
        $scope.attckThtrList.forEach(function (item, index) {
    		$scope.compareUIandCVE('AttackTheater',item);
    	});
        $scope.lgclImpctList.forEach(function (item, index) {
    		$scope.compareUIandCVE('LogicalImpact',item);
    	});
        
        return $scope.vdoUpdates.update;
    }
    
    $scope.disableRB = function(rbID, disabledState){
    	document.getElementById(rbID).disabled = disabledState;
    }
    
    $scope.uncheckCB = function(name){
    	$scope.check('ch'+name,false);
    }
    $scope.checkCB = function(name){
    	$scope.check('ch'+name,true);
    }
    
    $scope.check = function(elementID, state) {
        document.getElementById(elementID).checked = state;
    }
    
    $scope.select = function(cveItem, $index) {
    	$scope.currentCVEnum = $scope.currentPage*$scope.itemsPerPage + $index;
    	$scope.currentIndexInPage = $index;
    	$scope.selectedCVEpage = $scope.currentPage;
        $scope.selected = cveItem;
        $scope.getCVEdetails(cveItem.cve_id);
        
//        $scope.review.currentCVEdesc = cveItem.description;
      };
      
      $scope.highlightSelectedInit = function(){
    	  $timeout(function() {
    		  $scope.highlightSelected();
    	  }, 0);
      }
      
      $scope.highlightSelected = function(){
    	  
    	  if ($scope.cveToShow.length<=0)
    		  return;
    	  var cveID = $scope.searchResults[$scope.currentCVEnum].cve_id;
    	  var i;
    	  for(i=0; i<$scope.cveToShow.length; i++){
    		  var listItem = document.getElementById($scope.cveToShow[i].cve_id + "ListItem");
    		  listItem.style.backgroundColor = null;
    	  }
    	  
    	  var selectedItem = document.getElementById(cveID + "ListItem");
    	  
    	  if (selectedItem==null)
    		  return;
    	  
    	  selectedItem.style.backgroundColor = "powderblue";
    	  
    	  
      }
      
    $scope.updateCVEstatusInList = function(statusID){
    	if($scope.cveToShow.length<=0){
    		return;
    	}
    	
    	if ($scope.currentPage==$scope.selectedCVEpage){
    		$scope.cveToShow[$scope.currentIndexInPage].status_id = statusID;
    	}
    	$scope.searchResults[$scope.currentCVEnum].status_id = statusID;
    }
    
    function formatDate(date) {
        return date.getFullYear() + '-' + ((date.getMonth() > 8) ? (date.getMonth() + 1) : ('0' + (date.getMonth() + 1)))  + '-' + ((date.getDate() > 9) ? date.getDate() : ('0' + date.getDate()));
    }
    
    $scope.showPage = function(pageNum){
    	if ($scope.searchResults.length<1 || pageNum<0){
    		return;
    	}
    	
    	var startIndex = pageNum * $scope.itemsPerPage;
    	
    	if (startIndex >= $scope.searchResults.length){
    		return;
    	}
    	
    	$scope.currentPage = pageNum;
    	$scope.review.jumpTo = pageNum + 1;
    	$scope.cveToShow = [];
    	var i;
    	for (i=startIndex; i<startIndex+$scope.itemsPerPage && i<$scope.searchResults.length; i++){
    		$scope.cveToShow.push($scope.searchResults[i]);
    	}
    	
//    	$scope.highlightSelected();
    }
    
    $scope.nextPage = function(){
		$scope.showPage($scope.currentPage + 1);
	}
	
	$scope.prevPage = function(){
		$scope.showPage($scope.currentPage - 1);
	};
	
	$scope.goToPage = function(){
		$scope.showPage($scope.review.jumpTo-1);
	}	
    	
	$scope.getCVEdetails = function (cveID) {
		
		var username = $cookieStore.get('nvip_user').username;
		var token = $cookieStore.get('nvip_user').token;
				
		if (username==null || username=="" || token==null || token==""){
			alert("You are not logged in!");
			$cookieStore.remove('nvip_user');
			window.location.reload();
		}

		$scope.review.currentCVEdesc = '';
    	$scope.cveDetails = '';
    	$scope.review.readableStatus = '';
		$scope.review.impactScore = '';
		$scope.setCVSSseverity($scope.cveDetails.cvss_class);
    	
		$scope.toggleDetailsLoading(true);
		
		$http({
            url : 'reviewServlet',
            method : "GET",  
            params : {cveID : cveID, username:username, token:token}       
        }).then(function(response) {
        	
        	$scope.toggleDetailsLoading(false);
            
        	$scope.cveDetails = response.data;

			if ($scope.selected === "" || $scope.selected === undefined) {
				$scope.selected = $scope.cveDetails;
			}

        	$scope.processDetails();
        	$scope.highlightSelected();

            // Hide the loading bar now that the results have arrived
            
            
        }, function(response) {
            console.log("Failure -> " + response.data);
            
            // Hide the loading bar now that request has failed
            $scope.toggleDetailsLoading(false);
            
            if (response.status == 401){
            	alert(response.data);
            	window.location.assign(window.location.href+"login");
            }
            else{
            	alert(response.data);
            }
            
            $scope.review.currentCVEdesc = '';
        	$scope.cveDetails = '';
        });
	};
	
	$scope.processDetails = function(){
		$scope.review.currentCVEdesc = $scope.cveDetails.description;
		$scope.review.readableStatus = $scope.getStatusName($scope.cveDetails.status_id);
		$scope.review.impactScore = parseFloat($scope.cveDetails.impact_score);
		$scope.setCVSSseverity($scope.cveDetails.cvss_class);
		
		if($scope.cveDetails.userName==null){
			$scope.userName = 'NVIP';
		}
		else{
			$scope.userName = $scope.cveDetails.userName;
		}
		
		if($scope.cveDetails.updateDate!=null){
			$scope.updateDate = $scope.cveDetails.updateDate;
		}
		else{
			//$scope.updateDate = $scope.selected.run_date_time;
			$scope.updateDate = $scope.cveDetails.run_date_time;
		}
		
		
		var vdoGroups = $scope.cveDetails.vdoGroups;
		$scope.disableAllRB();

		if (vdoGroups !== undefined) {
			for ([group, groupValue] of Object.entries(vdoGroups)){
				var groupLabels = groupValue.vdoLabel;
				for ([vdoLabel, vdoConfidence] of Object.entries(groupLabels)){
					$scope.checkCB(vdoLabel);
					$scope.enableRBgroup(vdoLabel, vdoConfidence);
				}
			}
		}
	}
	
	$scope.setCVSSseverity = function(severity){
		document.getElementById("severityClassRBgroup").removeAttribute('class');
    	
		if (severity === "LOW"){
			document.getElementById("severityClassRBgroup").classList.add("review-cvsslow");
			document.getElementById("severiryLow").checked=true;
		}
		else if (severity === "MEDIUM"){
			document.getElementById("severityClassRBgroup").classList.add("review-cvssmedium");
			document.getElementById("severiryMedium").checked=true;
		}
		else if (severity === "HIGH"){
			document.getElementById("severityClassRBgroup").classList.add("review-cvsshigh");
			document.getElementById("severiryHigh").checked=true;
		}
		else if (severity === "CRITICAL"){
			document.getElementById("severityClassRBgroup").classList.add("review-cvsscritical");
			document.getElementById("severiryCritical").checked=true;
		}
	}
	
	$scope.getStatusName = function(statusID){
		if (statusID == 1 || statusID == null){
			return "Crawled";
		}
		if (statusID == 2){
			return "Rejected";
		}
		if (statusID == 3){
			return "Under Review";
		}
		if (statusID == 4){
			return "Accepted";
		}
	}
	
	$scope.yyyymmddToLocalDate = function(isoString) {
		  const [year, month, day] = isoString.split('-');
		  return new Date(year, month - 1, day);
		}
	
	$scope.nextDay = function(){
		$scope.addDays(1);
		$scope.searchCVEs();
	}
	
	$scope.prevDay = function(){
		$scope.addDays(-1);
		$scope.searchCVEs();
	}
	
	$scope.addDays = function(days){
		var newDate = new Date($scope.yyyymmddToLocalDate($scope.review.curDate));
		newDate.setDate(newDate.getDate()+days);
		$scope.review.curDate = formatDate(newDate);
	}
    
	/**
	 * Queries the database for vulnerabilities matching the search criteria entered 
	 * in the search form.
	 * @param {Object} event - (Optional) Event object from Search Form submit button. 
	 * If is null, coming from another source (i.e. loading adding entries from paging bar) 
	 * that does not need to switch the Search Form appearance.
	 * @param {number} limitCount - (Optional) Number of entries that will be requested from the database 
	 * @param {boolean} isBefore - (Optional) Used to determine if the retrieved values will be from an earlier index (vulnId)
	 * than the one used for the query. Based on page number
	 */
	$scope.searchCVEs = function () {
		
		var username = $cookieStore.get('nvip_user').username;
		var token = $cookieStore.get('nvip_user').token;
				
		if (username==null || username=="" || token==null || token==""){
			alert("You are not logged in!");
			$cookieStore.remove('nvip_user');
			window.location.reload();
		}
		
		var selectedDate = $scope.review.curDate;
		
		var crawled = document.getElementById("chCrawled").checked;
		var rejected = document.getElementById("chRejected").checked;
		var accepted = document.getElementById("chAccepted").checked;
		var reviewed = document.getElementById("chReview").checked;
		
		$scope.searchResults = {};
        $scope.filteredSearchResults = {};
        $scope.cveToShow=[];
		
		$scope.toggleListLoading(true);
		
		$http({
            url : 'reviewServlet',
            method : "GET",  
            params : {username: username, token:token, searchDate : selectedDate, crawled:crawled, rejected:rejected, accepted:accepted, reviewed:reviewed}       
        }).then(function(response) {
        	
        	$scope.toggleListLoading(false);
            //console.log(response.data);
            $scope.resultTotalCount = response.data.pop(response.data.length-1);
            $scope.totalCVEs = $scope.resultTotalCount;
            $scope.searchResults = response.data;
            
            
            if ($scope.totalCVEs>0){
            	$scope.totalPages = Math.ceil($scope.totalCVEs/$scope.itemsPerPage);
            	$scope.showPage(0);
            	$scope.select($scope.searchResults[0],0);
            }
            else{
            	$scope.cveToShow=[];
            }
                        
        }, function(response) {
            console.log("Failure -> " + response.data);
                        
            // Hide the loading bar now that request has failed
            $scope.toggleListLoading(false);
            
            if (response.status == 401){
            	alert(response.data);
            	window.location.assign(window.location.href+"login");
            }
            else{
            	alert(response.data);
            }
            
            
            $scope.searchResults = {};
            $scope.filteredSearchResults = {};
            $scope.cveToShow=[];
        });
	};
	
	$scope.showCVE = function(cveNum){
		if (cveNum>=0 && cveNum<$scope.totalCVEs){
			$scope.currentCVEnum = cveNum;
			$scope.currentCVEnumDisplay = cveNum + 1;
			$scope.review.jumpTo = $scope.currentCVEnumDisplay;
			$scope.currentCVE = $scope.searchResults[cveNum];
			$scope.currentCVEid = $scope.currentCVE.cveId;
			$scope.review.currentCVEdesc = $scope.currentCVE.description;
		}
		
	}
	
	$scope.nextCVE = function(){
		if ($scope.searchResults.length===0 || $scope.searchResults.length === undefined || $scope.currentCVEnum>=$scope.searchResults.length-1)
			return;
		
		if($scope.currentIndexInPage>=$scope.itemsPerPage-1){
			$scope.selectedCVEpage = $scope.selectedCVEpage + 1;
//			$scope.nextPage();
			if ($scope.currentPage!=$scope.selectedCVEpage){
				$scope.showPage($scope.selectedCVEpage);
			}
			$scope.select($scope.searchResults[$scope.currentCVEnum + 1],0);
		}
		else{
			if ($scope.currentPage!=$scope.selectedCVEpage){
				$scope.showPage($scope.selectedCVEpage);
			}
			$scope.select($scope.searchResults[$scope.currentCVEnum + 1],$scope.currentIndexInPage+1);
		}
		
		
		
//		$scope.currentCVEnum = $scope.currentCVEnum + 1;
//		$scope.selected = $scope.searchResults[$scope.currentCVEnum];
//		$scope.getCVEdetails($scope.searchResults[$scope.currentCVEnum].cve_id);
	}
	
	$scope.prevCVE = function(){
		if ($scope.searchResults.length==0 || $scope.searchResults.length === undefined || $scope.currentCVEnum==0)
			return;
		
		if($scope.currentIndexInPage<=0){
//			$scope.prevPage();
			$scope.selectedCVEpage = $scope.selectedCVEpage - 1;
			if ($scope.currentPage!=$scope.selectedCVEpage){
				$scope.showPage($scope.selectedCVEpage);
			}
			$scope.select($scope.searchResults[$scope.currentCVEnum - 1],$scope.itemsPerPage-1);
		}
		else{
			if ($scope.currentPage!=$scope.selectedCVEpage){
				$scope.showPage($scope.selectedCVEpage);
			}
			$scope.select($scope.searchResults[$scope.currentCVEnum - 1],$scope.currentIndexInPage-1);
		}
		
//		$scope.currentCVEnum = $scope.currentCVEnum - 1;
//		$scope.selected = $scope.searchResults[$scope.currentCVEnum];
//		$scope.getCVEdetails($scope.searchResults[$scope.currentCVEnum].cve_id);
	};
	
	$scope.goToCVE = function(){
		$scope.showCVE($scope.review.jumpTo-1);
	}	
	
	$scope.toggleDetailsLoading = function(show){
		$scope.toggleLoading("detailsProgressCircle", show);
	}
	
	$scope.toggleListLoading = function(show){
		$scope.toggleLoading("listProgressCircle", show);
	}
	
	$scope.toggleLoading = function(elementID, show){
		var loadingCircle = document.getElementById(elementID);
		
		if (loadingCircle != null){

			if (show){
				loadingCircle.style.display = "block";
			}
			else{
				loadingCircle.style.display = "none";
			}
		}
		
	}
	
	
	/** Toggles the appearance of the Search Form and Search Results */
	$scope.toggleSearchForm = function(){	
		searchFormBtn = document.getElementsByClassName("nvip-form-btn")[0];
		
		if ($scope.showForm){
			$scope.showForm = false;
			searchFormBtn.disabled = true;
		}
		else {
			// Re-enable the Search Form submmit button if it has been disabled
			$scope.showForm = true;
			searchFormBtn.disabled = false;
		}
	}
	
	$scope.atomicUpdateCVE = async function (statusID, changeDescription) {
		var username = $cookieStore.get('nvip_user').username;
		var token = $cookieStore.get('nvip_user').token;

		if (username == null || username == "" || token == null || token == "") {
			alert("You are not logged in!");
			$cookieStore.remove('nvip_user');
			window.location.reload();
		}

		var tweet = document.getElementById("chTweet").checked;

//		console.log("USER ID is " + userID);
//		var info = "CVE is accepted";

		if ($scope.cveDetails === null || $scope.cveDetails === "") {
			await new Promise(r => setTimeout(r, 10000));
		}

		$scope.toggleDetailsLoading(true);
		$http({
			url: 'reviewServlet',
			method: "POST",
			headers: {
				'Content-Type': 'Text/plain',
			},
			params: {
				atomicUpdate: true,
				username: username,
				token: token,
				statusID: statusID,
				vulnID: $scope.cveDetails.vuln_id,
				cveID: $scope.cveDetails.cve_id,
				info: changeDescription,
				tweet: tweet
			},
//            params : {acceptCVE:true, vulnID:$scope.cveDetails.vuln_id, cveID:$scope.cveDetails.cve_id, userID:userID, description:$scope.cveDetails.description, info:info}       
			data: $scope.cveDetails.description,
		}).then(function (response) {

			$scope.reviewMessage = changeDescription;

			if (statusID === 4) {
				document.getElementById("nvip_message_text").style.color = 'green';
			} else if (statusID === 2) {
				document.getElementById("nvip_message_text").style.color = 'red';
			}

			$scope.toggleDetailsLoading(false);

			$scope.getCVEdetails($scope.cveDetails.cve_id);

			$scope.updateCVEstatusInList(statusID);

			console.log(changeDescription);

		}, function (response) {
			console.log("Failure -> " + response.data);

			// Hide the loading bar now that request has failed
			$scope.toggleDetailsLoading(false);

			if (response.status == 401) {
				alert(response.data);
				window.location.assign(window.location.href + "login");
			} else {
				alert("ERROR!\n" + response.data);
			}

		});
	}
	
	$scope.acceptCVE = function(){
		$scope.atomicUpdateCVE(4, "CVE is accepted");
	}
	
	$scope.rejectCVE = function(){
		$scope.atomicUpdateCVE(2, "CVE is rejected");
	}
	
	$scope.getCVSSfromUI = function(){
		
		$scope.cvssFromUI = {
	    		cve_id:0,
	    		cvss_severity_id:0,
	    		severity_confidence:0,
	    		impact_score:0,
	    		impact_confidence:0
	    };
		$scope.cvssFromUI.cve_id = $scope.cveDetails.cve_id;
		if(document.getElementById("severiryLow").checked){
			$scope.cvssFromUI.cvss_severity_id=$scope.cvssClassMap.get('LOW');
		}
		else if(document.getElementById("severiryMedium").checked){
			$scope.cvssFromUI.cvss_severity_id=$scope.cvssClassMap.get('MEDIUM');
		}
		else if(document.getElementById("severiryHigh").checked){
			$scope.cvssFromUI.cvss_severity_id=$scope.cvssClassMap.get('HIGH');
		}
		else if(document.getElementById("severiryCritical").checked){
			$scope.cvssFromUI.cvss_severity_id=$scope.cvssClassMap.get('CRITICAL');
		}
		
		$scope.cvssFromUI.severity_confidence=1;
		$scope.cvssFromUI.impact_score = $scope.review.impactScore;
		$scope.cvssFromUI.impact_confidence=1;

	}
	
	$scope.isCVSSupdated = function(){
		$scope.getCVSSfromUI();
		
		if ($scope.cveDetails.impact_score != $scope.cvssFromUI.impact_score)
			return true;
		
		if ($scope.cvssClassMap.get($scope.cveDetails.cvss_class) != $scope.cvssFromUI.cvss_severity_id)
			return true;
				
		return false;
	}
	
	$scope.getProductsToRemove = function(){
		
		var prodToRemove = [];
		if ($scope.cveDetails.vulnDomain.length<=0)
			return prodToRemove;
		
		var i=0;
		for (i=0; i<$scope.cveDetails.vulnDomain.length;i++){
			if(document.getElementById("chProduct" + $scope.cveDetails.vulnDomain[i].product_id).checked){
				prodToRemove.push($scope.cveDetails.vulnDomain[i].product_id);
			}
		}
		
		if (prodToRemove.length<=0)
			return prodToRemove;
		
		return prodToRemove;
		
	}
	
	$scope.updateButton = function(){
		var updateDescription = false;
		var updateVDO = false;
		var updateCVSS = false;
		var updateAffRel = false;
		
		if ($scope.review.currentCVEdesc!=$scope.cveDetails.description){
			updateDescription = true;
		}
		
		updateVDO = $scope.isChangeInVDO();
		updateCVSS = $scope.isCVSSupdated();
		
		var prodToRemove = $scope.getProductsToRemove();
		
		if (prodToRemove.length>0){
			updateAffRel=true;
			$scope.productsRemove = prodToRemove;
		}
		
		console.log("Update description: " + updateDescription);		
		console.log("Update vdo: " + updateVDO);
		console.log("Update CVSS: " + updateCVSS);
		console.log("Update Affected Release: " + updateAffRel);
		
		$scope.updateCVE(updateDescription, updateVDO, updateCVSS, updateAffRel, 3, prodToRemove);
	
//		console.log("CVSS JSON: " + JSON.stringify($scope.cvssFromUI));
//		console.log("Affected Release JSON: " + JSON.stringify(prodToRemove));
//		console.log("VDO JSON: " + JSON.stringify($scope.vdoUpdates));
		
	}
	
	$scope.updateCVE = function (updateDescription, updateVDO, updateCVSS, updateAffRel, statusID, prodToRemove) {

		var username = $cookieStore.get('nvip_user').username;
		var token = $cookieStore.get('nvip_user').token;
				
		if (username==null || username=="" || token==null || token==""){
			alert("You are not logged in!");
			$cookieStore.remove('nvip_user');
			window.location.reload();
		}
		
		var vdoJSON = "";
		var cvssJSON = "";
		var productsToRemoveJSON = "";
		var descriptionToUpdate = "";
		var dataToSend = {};
		
		var userID = $cookieStore.get('nvip_user').userID;
		
		if (updateDescription){
			descriptionToUpdate = descriptionToUpdate + "Description update; "
			dataToSend.description = $scope.review.currentCVEdesc;
		}
		
		if (updateVDO){
			dataToSend.vdoUpdates=$scope.vdoUpdates;
//			vdoJSON = JSON.stringify($scope.vdoUpdates);
			descriptionToUpdate = descriptionToUpdate + "VDO update; "
		}
		
		if (updateCVSS){
			dataToSend.cvss=$scope.cvssFromUI;
//			cvssJSON = JSON.stringify($scope.cvssFromUI);
			descriptionToUpdate = descriptionToUpdate + "CVSS update; "
		}
		
		if (updateAffRel){
			dataToSend.prodToRemove=prodToRemove;
//			productsToRemoveJSON = JSON.stringify(prodToRemove);
			descriptionToUpdate = descriptionToUpdate + "Removed some products; "
		}
		
		dataToSend.descriptionToUpdate = descriptionToUpdate;
		var dataToSendString = JSON.stringify(dataToSend);
		
		$scope.toggleDetailsLoading(true);
//		
//        params : {complexUpdate:true, updateDescription:updateDescription, updateVDO:updateVDO, updateCVSS:updateCVSS, updateAffRel:updateAffRel, 
//        	vulnID : $scope.currentCVE.vulnId, cveID:$scope.cveDetails.cve_id, descriptionToUpdate:descriptionToUpdate, userID:userID,
//        	description:$scope.review.currentCVEdesc, vdoJSON:vdoJSON, cvssJSON:cvssJSON, productsToRemoveJSON:productsToRemoveJSON}  
		
		$http({
            url : 'reviewServlet',
            method : "POST", 
            headers: {
                'Content-Type': 'application/json',
              },
            params : {complexUpdate:true, username: username, token: token, updateDescription:updateDescription, updateVDO:updateVDO, updateCVSS:updateCVSS, updateAffRel:updateAffRel, 
            	vulnID : $scope.cveDetails.vuln_id, cveID:$scope.cveDetails.cve_id, statusID:statusID},
            data : dataToSendString,
        }).then(function(response) {
                       
            // Hide the loading bar now that the results have arrived
        	$scope.toggleDetailsLoading(false);
        	
        	$scope.getCVEdetails($scope.cveDetails.cve_id);
        	
        	$scope.updateCVEstatusInList(statusID);

            
        }, function(response) {
            console.log("Failure -> " + response.data);
            
            // Hide the loading bar now that request has failed
            $scope.toggleDetailsLoading(false);
            
            if (response.status == 401){
            	alert(response.data);
            	window.location.assign(window.location.href+"login");
            }
            else{
            	alert(response.data);
            }
            
        });
	};
	
	$scope.updateDailyVulns = function(){
		
		var r = confirm($scope.textForDailyUpdateWarning);
		if(r==false)
			return;
	
		var username = $cookieStore.get('nvip_user').username;
		var token = $cookieStore.get('nvip_user').token;
				
		if (username==null || username=="" || token==null || token==""){
			alert("You are not logged in!");
			$cookieStore.remove('nvip_user');
			window.location.reload();
		}
		
		$scope.toggleDetailsLoading(true);
		
		$http({
            url : 'reviewServlet',
            method : "POST",  
            params : {updateDailyTable:true, username: username, token: token}
        }).then(function(response) {
            //console.log(response.data);
        	
        	$scope.toggleDetailsLoading(false);
        	
        	var responseNum = response.data;
        	
        	alert("Update is Finished!\n" + responseNum + " records were generated.");

        }, function(response) {
            console.log("Failure -> " + response.data);
            
            // Hide the loading bar now that request has failed
            $scope.toggleDetailsLoading(false);
            
            if (response.status == 401){
            	alert(response.data);
            	window.location.assign(window.location.href+"login");
            }
            else{
            	alert("ERROR!\n" + response.data);
            }
            
            

        });
	}
	
	/** Initialization code **/
    $scope.init();
    
} ]);

//app.directive('myPostRepeatDirective', function() {
//  return function(scope, element, attrs) {
//    if (scope.$last){
//      // iteration is complete, do whatever post-processing
//      // is necessary
////      element.parent().css('border', '1px solid black');
//    	scope.highlightSelected();
//    }
//  };
//});