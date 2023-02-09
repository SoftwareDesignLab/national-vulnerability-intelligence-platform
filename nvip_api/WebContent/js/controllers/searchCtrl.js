app.controller('SearchController', [ '$scope', '$rootScope', '$http', '$routeParams', '$cookieStore', '$window', 'Results', 'FormCheck',
 function($scope, $rootScope, $http, $routeParams, $cookieStore, $window, Results, FormCheck) {
     
    $http.defaults.headers.post["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
    
    // Search Form Parameters
    $scope.cvssScores = [];
    $scope.search = {};
    $scope.search.vulnId = 0; // Initially set to 0
    $scope.showForm = true;
    $scope.vdoNounGroupLabels = [];
    
    // Paging Parameters
    $scope.currentPage = 0;
    $scope.pageBlocks = [];
    $scope.pageLimit = 10;
    $scope.pageOffset = 0;
    $scope.totalPageLimit = 10;
    $scope.totalPages = 0;
    
    // Search Result Parameters
    $scope.filteredSearchResults = {};
    $scope.searchResults = {};
    
    $scope.init = function () {
	
		var formCheck = FormCheck.get();
	
		if (formCheck != null || formCheck != undefined) {
			if (formCheck) {
				$scope.showForm = true;
			} else {
				$scope.showForm = false;
				$scope.searchResults = Results.get();
				
	            $scope.resultTotalCount = $scope.searchResults.length;
				
				if ($scope.resultTotalCount < 10) {
					$scope.totalPageLimit = 1;
				} else {
					$scope.totalPageLimit = ($scope.resultTotalCount / 10) | 0;
				}
				
	            $scope.filteredSearchResults = $scope.searchResults.slice($scope.pageOffset, ($scope.pageOffset + $scope.pageLimit));
	            $scope.getTotalPages($scope.resultTotalCount);
	            $scope.updatePages($scope.searchResults.length);
				
				FormCheck.set(true);
			}
		}
	
    	$scope.getSearchFormInfo();
		
    };
	
	$scope.storeResults = function(vulnId) {
		$window.location.href = "#vulnerability/"+vulnId;
	}
	
	 function formatDate(date) {
        return date.getFullYear() + '-' + ((date.getMonth() > 8) ? (date.getMonth() + 1) : ('0' + (date.getMonth() + 1)))  + '-' + ((date.getDate() > 9) ? date.getDate() : ('0' + date.getDate()));
    }
    
    /** Controller Functions **/
    
	/** Paging Functions **/
	
    /**
     * Changes the search result page to the given page number. 
     * Does nothing if the page is same as the current page
     */
    $scope.changePage = function(pageNum){
    	//console.log("Change Page: " + pageNum);
    	
    	// If the page number is not the current page, switch pages
    	if($scope.currentPage != pageNum){
    		var oldOffset = $scope.pageOffset;
	    	$scope.pageOffset = ($scope.pageLimit * pageNum); 
	    	$scope.currentPage = pageNum;
	    	
	    	//var isBefore = $scope.currentPage > pageNum ? $scope.filteredSearchResults[0].vulnId : $scope.filteredSearchResults[-1].vulnId;
	    	var limitCount = $scope.pageLimit * Math.abs($scope.currentPage - pageNum);
	    	
	    	// If the offset index is beyond the available indicies in the current search
	    	// result, pull from the database
	    	if($scope.pageOffset >= $scope.searchResults.length){
	    		// console.log("Hits this");
	    		// $scope.searchVulns(limitCount, ascending);
	    	}
	    	else{
	    		// Modify the filtered results to show the desired values
	    		$scope.filteredSearchResults = $scope.searchResults.slice($scope.pageOffset, ($scope.pageOffset + $scope.pageLimit));
	    	}
	    	
	    	$scope.updatePages($scope.searchResults.length);
    	}
    }
    
    /**
    * Sets the page to the first page and updates the paging blocks accordingly.
    **/
    $scope.firstPage = function(){
    	$scope.changePage(0);
    }
	
	/**
	* Gets the total number of pages that can be generated from the search results
	* @param {number} totalCount - Total number of entities in the results that will be divided into pages
	*/
	$scope.getTotalPages = function(totalCount){
		var totalPages = (totalCount % $scope.pageLimit) == 0 ? (totalCount / $scope.pageLimit) :
					Math.floor(totalCount / $scope.pageLimit) + 1;
			
		// Set the total number of pages
		$scope.totalPages = totalPages;
	}
	
	/**
    * Sets the page to the last page and updates the paging blocks accordingly.
    */
	$scope.lastPage = function() {
		$scope.changePage($scope.totalPages - 1);
	}
	
	/**
	* Sets the current page to the immediate next page index and updates 
	* the page blocks accordingly.
	**/
	$scope.nextPage = function() {
		if ($scope.currentPage + 1 < $scope.totalPages) {
			$scope.changePage($scope.currentPage + 1);
		}
	}
	
	/**
	* Sets the current page to the immediate previous page index and updates 
	* the page blocks accordingly.
	**/
	$scope.previousPage = function() {
		if ($scope.currentPage - 1 >= 0) {
			$scope.changePage($scope.currentPage - 1);
		}
	}
	
	/**
	 * Updates the list of inidices representing the pages to be shown up to the defined maximum # of 
	 * pages. Indicies based from the current page. Attempts to put an equal number of pages before and after the current page
	 * @param {number} totalEntries - Total number of entries. Will be used in the display 
	 * the page record range
	 */
	$scope.updatePages = function(totalEntries){
		
		// If there are no entries, skip this method
		if (totalEntries == 0) {
			$scope.pageBlocks = [];
			$scope.pageRecord = [0, 0];
			return;
		}
		
		var numPages = $scope.totalPageLimit <= 1 ? 0 : Math.floor($scope.totalPageLimit/2) - 1;
		var start = $scope.currentPage - numPages < 0 ? 0 : $scope.currentPage - numPages;
		var end =  $scope.currentPage + numPages > $scope.totalPages ? $scope.totalPages : (($scope.currentPage + numPages) + 1);
			
		// If the ending page is before the total allowed number of pages, set it to the 
		// total number of pages allowed
		if (end < $scope.totalPageLimit)
			end = $scope.totalPageLimit;
		
		var pageBlocks = [];
		for (i = 0; i < $scope.totalPageLimit+1 && i < 10; i++) {
			pageBlocks.push(i);
		}
		
		// Calculate the record range based on the current page and the total 
		// number of entries
		$scope.pageRecord = [((($scope.currentPage) * $scope.pageLimit) + 1), 
					(($scope.currentPage + 1) * $scope.pageLimit) > totalEntries 
					? totalEntries : (($scope.currentPage + 1) * $scope.pageLimit)];
			
		$scope.pageBlocks = pageBlocks;
	}
	
	
	/** Search Result Functions **/
	
	/**
	 * Formats the search values that will be sent to the servlet. Handles cases where all values 
	 * of a given subcategory (i.e. VDO labels) are selected
	 **/

	$scope.formatSearchParameters = function(search){
		
		// CVSS Scores
		$scope.search.cvssScores = [];
		for(i = 0; i < $scope.cvssScores.length; i++){
			if($scope.cvssScores[i] == true){
				$scope.search.cvssScores.push($scope.searchInfo.cvssScores[i]);
			}
		}
		
		if($scope.search.cvssScores.length == 0){
			$scope.search.cvssScores = null;
		}
		
		// VDO Labels
		$scope.search.vdoLabels = [];
		
		if($scope.vdoLabels == undefined || $scope.vdoLabels.length == 0){
			$scope.search.vdoLabels = null;
		}
		angular.forEach($scope.vdoLabels, function(vdoLabels, vdoNounGroup){
			for(i = 0; i < vdoLabels.length; i++){
				if (vdoLabels[i] == true){
					$scope.search.vdoLabels.push($scope.searchInfo.vdoEntityLabels[vdoNounGroup][i]);
				}
			}
		});
		
		// If no labels were selected, set the VDO Labels field to null
		if ($scope.search.vdoLabels == null || $scope.search.vdoLabels.length == 0){
			$scope.search.vdoLabels = null;
		}
		
		// Site Presence
		
		// Replaces any empty values with null so that the site list can
		// be properly passed to the servlet
//		for(i = 0; i < $scope.search.sites.length; i++){
//			if ($scope.search.sites[i] == null || $scope.search.sites[i] == undefined){
//				$scope.search.sites[i] = true;
//			}
//		}
	}
	
	$scope.getSearchFormInfo = function() {
		
		var username = $cookieStore.get('nvip_user').username;
		var token = $cookieStore.get('nvip_user').token;
				
		if (username==null || username=="" || token==null || token==""){
			alert("You are not logged in!");
			$cookieStore.remove('nvip_user');
			window.location.reload();
		}
		
		$http({
	        url : 'searchServlet',
	        method : "GET",  
	        params : {searchInfo: true, username: username, token: token}    
	    }).then(function(response) {
	        $scope.searchInfo = $scope.parseSearchMap(response.data);
	    }, function(response) {
	        console.log("Failure -> " + response.data);
	        $scope.searchInfo = response.data;
	        if (response.status == 401){
            	alert(response.data);
            	window.location.assign(window.location.href+"login");

            }
	    });
	}
	
	/** Parses the Search Form values from the servlet so that the form can 
	 * be initialized. 
	 * @param {Object} searchMap - Object containing all the Search Form information 
	 * (i.e. available CVSS Score, VDO labels, known sites, etc.) that can be parsed to 
	 * initialize the Search Form **/
	$scope.parseSearchMap = function(searchMap){
		// Initial Search Form parameter object

		$scope.cvssScores = new Array(searchMap.cvssScores.cvssScores.length);
		var vdoNounGroupLabels = [];
		var vdoEntityLabels = {};
		$scope.vdoLabels = {};

		
		// Populate the search result variable with the parameters
		//$scope.search.sites = new Array(2);
		
		angular.forEach(searchMap.vdoNounGroups, function(vdoLabelArr, vdoNounGroup){
			vdoNounGroupLabels.push(vdoNounGroup);
			vdoEntityLabels[vdoNounGroup] = vdoLabelArr.sort();
			$scope.vdoLabels[vdoNounGroup] = new Array(vdoLabelArr.length);
		});
		
		// Initialize the VDO Noun Group field for the Search Form now that all noun groups 
		// are known.
		$scope.vdoNounGroups = new Array(vdoNounGroupLabels.length);
		
		return {cvssScores : searchMap.cvssScores.cvssScores, vdoNounGroupLabels : vdoNounGroupLabels.sort(), vdoNounGroups : searchMap.vdoNounGroups,
			vdoEntityLabels : vdoEntityLabels, vdoLabels : $scope.vdoLabels, siteLabels : ["MITRE", "NVD"]};
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
	$scope.searchVulns = function (event, limitCount, isBefore) {
		
		// Retrieve the search form button and disable it
		var searchFormBtn = null;
		
		if(event == null){
			searchFormBtn = document.getElementsByClassName("nvip-form-btn")[0];
		}
		else {
			searchFormBtn = getAncestor(event.srcElement, "nvip-form-btn");
		}
		
		// Prevent multiple calls to the database if the button is currently 
		// disabled (i.e. waiting for a query to complete)
		if (searchFormBtn.disabled != true){
			
			document.getElementById("searchKeyWordError").style.display = "none";
			document.getElementById("searchLimitError").style.display = "none";
			
			var username = $cookieStore.get('nvip_user').username;
			var token = $cookieStore.get('nvip_user').token;
					
			if (username==null || username=="" || token==null || token==""){
				alert("You are not logged in!");
				$cookieStore.remove('nvip_user');
				window.location.reload();
			}
			
			if (($scope.search.keyword === undefined || $scope.search.keyword.length < 2) && $scope.search.cve_id === undefined){
				document.getElementById("searchKeyWordError").style.display = "block";
				return
			}
			
			if (!Number.isInteger($scope.search.limit) && $scope.search.limit !== null && $scope.search.limit !== undefined) {
				console.log($scope.search.limit);
				document.getElementById("searchLimitError").style.display = "block";
				document.getElementById("searchLimitError").innerText = "Please enter an integer for the limit";
				return
			} else if (Math.abs($scope.search.limit) > 100) {
				document.getElementById("searchLimitError").style.display = "block";
				document.getElementById("searchLimitError").innerText = "Please enter a limit less than or equal to 100";
				return
			} else if ($scope.search.limit === undefined || $scope.search.limit === null) {
				$scope.search.limit = 100;	
			}
			
			searchFormBtn.disabled = true;
			
			// Display the loading bar
			$scope.toggleLoading();
			
			$scope.formatSearchParameters($scope.search);
			
			$scope.searchResults = {};
			$scope.filteredSearchResults = {};
			
	    	$http({
	            url : 'searchServlet',
	            method : "GET",  
	            params : {username: username, token: token, vulnId : $scope.search.vulnId, keyword: $scope.search.keyword, cve_id: $scope.search.cve_id, cvssScores: $scope.search.cvssScores, startDate : $scope.search.startDate, endDate : $scope.search.endDate, 
	            	inSite: $scope.search.sites, vdoLabels: $scope.search.vdoLabels, limitCount: Math.abs($scope.search.limit), isBefore: isBefore, product: $scope.search.product}       
	        }).then(function(response) {
		
	            $scope.resultTotalCount = response.data.pop(response.data.length-1);
				
				if ($scope.resultTotalCount < 10) {
					$scope.totalPageLimit = 1;
				} else {
					$scope.totalPageLimit = Math.ceil($scope.resultTotalCount / 10) - 1;
				}
				
				$scope.currentPage = 0;
				
				
	            $scope.searchResults = response.data;
				Results.set($scope.searchResults);
	            $scope.filteredSearchResults = $scope.searchResults.slice(0, $scope.pageLimit);
	            $scope.getTotalPages($scope.resultTotalCount);
	            $scope.updatePages($scope.searchResults.length);
	            
	            // Hide the loading bar now that the results have arrived
	            $scope.toggleLoading();
	            
	            // Once the search results have been loaded, toggle the search form so that
	            // the search results now appear. Do not trigger if call launched not launched 
	            // from a form button event.
	            if (event != null){
	            	$scope.toggleSearchForm();
	            }
	            
	        }, function(response) {
	            
	            // Hide the loading bar now that request has failed
	            $scope.toggleLoading();
	            
	            $scope.searchResults = {};
	            $scope.filteredSearchResults = {};
	            
	            if (response.status == 401){
	            	alert(response.data);
	            	window.location.assign(window.location.href+"login");

	            }
	        });
		
			searchFormBtn.disabled = false;

		}
	};
	
	/**
	 * Toggles the display of the content block below a dropdown in the form.
	 * @param {Object} event - Triggering event object for the action. Contains 
	 * the triggering element.
	 */
	$scope.toggleContent = function(event){
		// If the triggering element is a form checkbox, do not toggle.
		if (event.srcElement.classList.contains("nvip-form-dropdown-checkbox")){
			return;
		}
		
		var formDropdown = getAncestor(event.srcElement, "nvip-form-dropdown-field");
		var formContent = getSiblingByClassName(formDropdown, "nvip-form-dropdown-content");
		var caretIcon = formDropdown.getElementsByClassName("nvip-form-dropdown-caret")[0];
		
		if(formContent.style.display == 'flex'){
			formDropdown.classList.remove('dropdown-opened');
			formContent.style.display = 'none';
        	caretIcon.classList.add("fa-angle-left");
        	caretIcon.classList.remove("fa-angle-down");
		}
		else{
			formDropdown.classList.add('dropdown-opened');
			formContent.style.display = 'flex';
			caretIcon.classList.remove("fa-angle-left");
	        caretIcon.classList.add("fa-angle-down");
		}
	}
	
	$scope.toggleLoading = function(className){
		
		// If not given a class name, toggle the first loading bar found
		if (className == null){
			var loadingBar = document.getElementsByClassName("nvip-loading-bar");
			
			if (loadingBar != null){
				loadingBar = loadingBar[0];
				
				if (window.getComputedStyle(loadingBar).display == "none"){
					loadingBar.style.display = 'block';
				}
				else {
					loadingBar.style.display = 'none';
				}
			}
			
			return;
		}
		
		var element = document.getElementsByClassName(className);

		if (element != null){
			var loadingBar = element[0].getElementsByClassName("nvip-loading-bar")[0];

			if (window.getComputedStyle(loadingBar).display == "none"){
				loadingBar.style.display = 'block';
			}
			else {
				loadingBar.style.display = 'none';
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
	
	
	
	
	
	/** Initialization code **/
    $scope.init();
	
	
} ]);