var app = angular.module("NVIP", ['ngCookies', 'ngRoute', 'googlechart']);

/** #Section Constants **/

app.constant('AUTH_EVENTS', {
    loginSuccess : 'auth-login-success',
    loginFailed : 'auth-login-failed',
    logoutSuccess : 'auth-logout-success',
    sessionTimeout : 'auth-session-timeout',
    notAuthenticated : 'auth-not-authenticated',
    notAuthorized : 'auth-not-authorized'
});

app.constant('USER_ROLES', {
    all : '*',
    admin : 'admin',
    user : 'user'
});

app.constant('VDO_NOUN_GROUPS', {
	all : '*',
	ATTACK_THEATER : 'AttackTheater',
	CONTEXT : 'Context',
	IMPACT_METHOD : 'ImpactMethod',
	LOGICAL_IMPACT : 'LogicalImpact',
	MITIGATION : 'Mitigation'
});

/** #Section Routing **/

app.config(function($routeProvider) {  
    $routeProvider  
  
    // route for the home page
    .when('/', {  
        templateUrl: 'views/main.html',  
        controller: 'MainController'
    })
    .when('/login', {  
        templateUrl: 'views/login.html',  
        controller: 'LoginController'
    })
    .when('/createaccount', {  
        templateUrl: 'views/create_account.html',  
        controller: 'CreateAccountController'
    })
    .when('/daily', {  
        templateUrl: 'views/dailyVulns.html',  
        controller: 'VulnerabilityController'
    })
    .when('/vulnerability/:vulnId', {  
        templateUrl: 'views/vulnerability.html',  
        controller: 'VulnerabilityController'  
    })
    .when('/search', {  
        templateUrl: 'views/search.html',  
        controller: 'SearchController'  
    })
    .when('/about', {  
        templateUrl: 'views/about.html',
        controller: ''
    })
    .when('/review', {  
        templateUrl: 'views/review.html',  
        controller: 'ReviewController'  
    })
    .when('/privacy', {  
        templateUrl: 'views/privacy.html',  
        controller: ''  
    })
    .otherwise({
        redirectTo: '/'
    });
  
}); 

app.run(['$rootScope', '$timeout', '$cookies', '$cookieStore', '$location', 'AUTH_EVENTS', 'AuthService',
	function ($rootScope, $timeout, $cookies, $cookieStore, $location, AUTH_EVENTS, AuthService) {
		// keep user logged in after page refresh
        /*$rootScope.globals = $cookieStore.get('globals') || {};
        if ($rootScope.globals.currentUser) {
            $http.defaults.headers.common['Authorization'] = 'Basic ' + $rootScope.globals.currentUser.authdata; // jshint ignore:line
        }*/
        $rootScope.$on('$locationChangeStart', function (event, next, current) {
        	var authorizedRoles = next;
        	        	     	
        	var pageWOauth = next.includes('/createaccount') || next.includes('/about') || next.includes('/privacy');
//        	var reviewPage = next.includes('/review');
//        	var createAccountPage = next.includes('/createaccount');
        	
        	//do nothing. authentication is not required
        	if (pageWOauth)
        		return;
        	
        	if(AuthService.isAuthenticated()) {
        		// Do nothing, let allow them to access full-site	
        		//console.log("Are authenticated");
        		var role = $cookieStore.get('nvip_user').userRole;
        		if (role!=null && role==1){
        			switchViewToAdmin(true, $timeout);
        		}
        	}
        	else {
        		// Re-direct to login page since they are not logged in
        		$location.path('login');
        	}
        	
            //if ($location.path() !== '/login' && !$rootScope.globals.currentUser) {
             //   $location.path('/login');
            //}
        });
}]);

/** #Section Services **/

app.factory('AuthService', function ($http, $cookies, $cookieStore, Session) {
	$http.defaults.headers.post["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
	
	var authService = {};
	 
	  authService.login = function (credentials) {
		  // Add Method to encrypt password
		  var password_hash = credentials.password;
		  var request = {
          	method: "GET",
          	params: {'userName': credentials.username, 'passwordHash': password_hash},
          	url: "loginServlet"
          };
		  
		  return $http(request)
		  	.then(function(response) {
		  		if (response.data!=null && response.data!=""){
		  			Session.create(1, response.data.userName, response.data.roleId, response.data.firstName, response.data.token, response.data.expirationDate, response.data.domain);
	            	$cookieStore.put('nvip_user', Session);
		  		}
		  	})
		  	.catch(function(response) {
	            console.log("Failure -> " + response.data);
				document.getElementById("loginMessage").style.display = "block";
				if (response.data.length < 51) {
					document.getElementById("loginMessage").innerText = response.data;
				} else {
					document.getElementById("loginMessage").innerText = "An error has occurred while logging in, please try again";
				}
				document.getElementById("loginForm").style.marginTop = "5.5em";
	        });
	  };
	 
	  authService.isAuthenticated = function () {
		  if($cookieStore.get('nvip_user') != null || $cookieStore.get('nvip_user') != undefined){
			  // May be more involved process to check if session identifier is legitimate
			 return ($cookieStore.get('nvip_user').id != null || $cookieStore.get('user').id != undefined);
		  }
		  
		  return false;
	  };
	 
	  authService.isAuthorized = function (authorizedRoles) {
	    if (!angular.isArray(authorizedRoles)) {
	      authorizedRoles = [authorizedRoles];
	    }
	    return (authService.isAuthenticated() &&
	      authorizedRoles.indexOf(Session.userRole) !== -1);
	  };
	 
	  return authService;
});


app.factory('Results', function() {
   var results = {}

       function set(data) {
           results = data;
       }
       function get() {
           return results;
       }

	return {
		set: set,
		get: get
	}
});

app.factory('FormCheck', function() {
	var formCheck = {}
	
	 function set(data) {
		formCheck = data;
	}
	function get() {
		return formCheck;
	}
	
	return {
		set: set,
		get: get
	}
})

app.service('Session', function () {
	this.create = function (sessionId, username, userRole, firstname, token, expiration) {
		this.id = sessionId;
		this.username = username;
		this.userRole = userRole;
		this.firstname = firstname;
		this.token = token;
		this.expiration = expiration;
	};
	
	this.destroy = function () {
		this.id = null;
		this.username = null;
		this.userRole = null;
		this.firstname = null;
		this.token = null;
		this.expiration = null;
	};
});

/** #Section Controllers **/

app.controller("VulnerabilityController", [ '$scope', '$http', '$routeParams', '$rootScope', 'AuthService', 'VDO_NOUN_GROUPS', '$cookieStore', '$timeout', '$window', 'FormCheck', 'Results',
function($scope, $http, $routeParams, $rootScope, AuthService, VDO_NOUN_GROUPS, $cookieStore, $timeout, $window, FormCheck, Results) {
     
    $http.defaults.headers.post["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
    $scope.vulnId = $routeParams.vulnId;
    $scope.vulnSearch = "";
    
    $scope.dailyVulnLimit = []; 
    $scope.vulnLimitIncr = 5;
    $scope.dailyVulnIndex = 0; // 0
    
    $scope.displayReviewButton = "";

    $scope.init = function (id) {
	    $scope.getDailyVulns();	    
  	};
  	
	/**
	 * Call the Search controller to retrieve the previous search results 
	 * once the back button is clicked
	 */

	$scope.setFormCheck = function(formCheck) {
		FormCheck.set(formCheck);
		$window.location.href = '#search/';	
	}

  	$scope.updateReviewButtonVisability = function(){
  		var role = $cookieStore.get('nvip_user').userRole;
    	var reviewButton = document.getElementById("divBtnOpenForReview");
	    if (role!=null && role==1){
//	    	$scope.displayReviewButton = "flex;";
	    	reviewButton.style.display = 'flex';
		}
	    else{
//	    	$scope.displayReviewButton = "none;";
	    	reviewButton.style.display = 'none';
	    }
  	}
  	
    $scope.getVulnInfo = function() {
    	
    	var username = $cookieStore.get('nvip_user').username;
		var token = $cookieStore.get('nvip_user').token;
				
		if (username==null || username=="" || token==null || token==""){
			alert("You are not logged in!");
			$cookieStore.remove('nvip_user');
			window.location.reload();
		}
    	
		$scope.toggleListLoading(true);
        $http({
            url : 'vulnerabilityServlet',
            method : "GET",  
            params : { vulnId : $scope.vulnId, username: username, token: token }       
        }).then(function(response) {
			$scope.toggleListLoading(false);
            if(response != null) {
                $scope.vuln = response.data;
                $scope.fillVulnTabs($scope.vuln);
            } else {
                console.log(response)
                $scope.vuln = null;
            }
        }, function(response) {
			$scope.toggleListLoading(false);
			if (response.status == 401){
            	alert(response.data);
            	window.location.assign(window.location.href+"login");
            }
            console.log("Failure -> " + response.data);
            $scope.vuln = null;
        });
    };
	
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


    $scope.getDailyVulns = function() {
    	

		//TODO Add user parameters for user daily digest (Recommended CVEs)
    	/*var username = $cookieStore.get('nvip_user').username;
		var token = $cookieStore.get('nvip_user').token;
				
		if (username==null || username=="" || token==null || token==""){
			alert("You are not logged in!");
			$cookieStore.remove('nvip_user');
			window.location.reload();
		}*/
    	
    	$scope.toggleLoadingScreen(true, "nvip-daily-vuln-ctn");
        $http({
            url : 'vulnerabilityServlet',
            method : "GET",  
            params : {daily: true, dateRange: 10/*, username: username, token: token*/} // 10      
        }).then(function(response) {
            $scope.dailyVulns = [];
            
            $scope.toggleLoadingScreen(false, "nvip-daily-vuln-ctn");
            
            angular.forEach(response.data, function(value, key) {
            	$scope.dailyVulnLimit.push($scope.vulnLimitIncr);
                $scope.dailyVulns.push({date: formatDate(value.date), cve_list: value.list});
            });
            //console.log($scope.dailyVulns);
        }, function(response) {
        	if (response.status == 401){
            	alert(response.data);
            	window.location.assign(window.location.href+"login");
            }
            console.log("Failure -> " + response.data);
            $scope.dailyVulns = response.data;
        });
    };
    
    $scope.searchFocusOut = function(){
        // console.log("Search bar lost focus");
    }
    $scope.searchVulns = function(vulnSearch){

        if (vulnSearch.length > 2) {
            $http({
                url : 'vulnerabilityServlet',
                method : "GET",  
                params : {match: "Gentoo"}       
            }).then(function(response) {
                console.log(response);
            }, function(response) {
                console.log("Failure -> " + response.data);
                $scope.dailyVulns = response.data.map;
            });
        }
    }
    
    $scope.fillVulnTabs = function(vuln) {
    	// Severity Tab
    	var cvssScores = vuln.cvssScoreList;
    	var cvssScoreLabels = [["Base", "Impact"]];

    	angular.forEach(cvssScores, function(cvssScore, key) {
			
    		if (key == 0) {
				google.charts.load('current', {'packages':['gauge']});
      			google.charts.setOnLoadCallback(setGauge);
				
				function setGauge() {

			        var data = google.visualization.arrayToDataTable([
			          ['Label', 'Value'],
			          ['Base', 0],
			          ['Impact', 0],
			        ]);
			
					if (cvssScore.baseSeverity == "CRITICAL") {
						data.setValue(0, 1, 9.0);
					}
					else if (cvssScore.baseSeverity == "HIGH") { 
						data.setValue(0, 1, 7.0);
					}
					else if (cvssScore.baseSeverity == "MEDIUM") { 
						data.setValue(0, 1, 5.0);
					}
					else if (cvssScore.baseSeverity == "LOW") { 
						data.setValue(0, 1, 3.0);
					}
					
					
					if (cvssScore != undefined && cvssScore != null) {
						data.setValue(1, 1, parseFloat(cvssScore.impactScore));
					}
			
					
			
			        var options = {
			          width: 800, height: 225,
			          redFrom: 6.9, redTo: 10,
			          yellowFrom: 5.5, yellowTo: 7.4,
					  greenFrom:0, greenTo: 6.5,
			          minorTicks: 6, max: 10,
			        };
			
			        var chart = new google.visualization.Gauge(document.getElementById('cvssGauge'));
			
			        chart.draw(data, options);
				}
    		}
    	});
		
		
    	// Characteristics Tabs
    	var vdoList = vuln.vdoList;
    	var vdoGraph = document.getElementsByClassName("vuln-characteristics-graph")[0];
		
		if (vdoGraph.innerHTML.length <= 0) {
			var vdoBar = null;
	    	var vdoBarText = null;
	    	vdoList.sort(function(vdo1, vdo2){
	    		var nounGroup1 = vdo1.vdoNounGroup;
	    		var nounGroup2 = vdo2.vdoNounGroup;
	    		
	    		var nounGroupCmp = nounGroup1.localeCompare(nounGroup2);
	    		
	    		if(nounGroupCmp == 0){
	    			
	    			if (vdo1.vdoConfidence == vdo2.vdoConfidence){
		    			var label1 = vdo1.vdoLabel;
		    			var label2 = vdo2.vdoLabel;
		    			
		    			return label1.localeCompare(label2);
	    			}
	    			else if(vdo1.vdoConfidence > vdo2.vdoConfidence){
	    				return -1;
	    			}
	    			else{
	    				return 1;
	    			}
	    		}
	    		else {
	    			return nounGroupCmp;
	    		}
	    	});
	    	
	    	angular.forEach(vdoList, function(vdo, key) {
	    		vdoBar = document.createElement("DIV");
				vdoBar.classList.add("vuln-characteristics-bar");
				
				vdoBarText = document.createElement("P");
				vdoBarText.innerText = vdo.vdoNounGroup + " : " + vdo.vdoLabel;
				vdoBar.appendChild(vdoBarText);
				
				vdoBarText = document.createElement("P");
				vdoBarText.innerText = (parseFloat(vdo.vdoConfidence)*100).toFixed(2)+"%";
				vdoBar.appendChild(vdoBarText);
				
				vdoGraph.appendChild(vdoBar);
	    	});
	    	
		}
    	$scope.updateReviewButtonVisability();
    }

    function getBarHeight(value) {
    	var barHeight = "2.5";
    	
    	if (isNaN(value))
    		return 0;
    		
    	return barHeight * value;
    }
    
    $scope.showLess = function(panelIndex){
    	var newLimit = $scope.dailyVulnLimit[panelIndex] - $scope.vulnLimitIncr;

    	if(newLimit < $scope.vulnLimitIncr) {
    		$scope.dailyVulnLimit[panelIndex] = $scope.vulnLimitIncr;
    	}
    	else {
    		$scope.dailyVulnLimit[panelIndex] = newLimit;
    	}
    }
    
    $scope.showMore = function(panelIndex){
    	$scope.dailyVulnLimit[panelIndex] = $scope.dailyVulnLimit[panelIndex] + $scope.vulnLimitIncr;
    }
    
    $scope.toggleLoadingScreen = function(loading, className){
    	// Show the loading screen
    	
    	if(className == "nvip-daily-vuln-ctn"){
    		var dailyVulnCtn = document.getElementsByClassName("nvip-daily-vuln-ctn")[0];
        	var loadingScreen = dailyVulnCtn.getElementsByClassName("nvip-loading-screen")[0];
        	//var panelCtns = dailyVulnCtn.getElementsByClassName("nvip-daily-vuln-panel-ctn");
        	
    		if(loading){
    			loadingScreen.style.display = 'block';
    		} 
    		else {
    			loadingScreen.style.display = 'none';
    			
    		}
    	}
    		
    }
    
	$scope.checkResults = function() {
		return (Results.get().length == null || Results.get().length == undefined);
	}

    // Main Page functions
    $scope.incrementDailyVulnDay = function(incr){
    	if($scope.dailyVulnIndex + incr < 0){
    		return;
    	}
    	else if ($scope.dailyVulnIndex + incr >= $scope.dailyVulns.length) {
    		return;
    	}
    	
    	$scope.dailyVulnIndex = $scope.dailyVulnIndex += incr;
    }
    
} ]);

/** #Section Global Functions **/



function getAncestor(element, className) {
	
	if (element == null) {
		return null;
	}
	
	// If the given element has the desired class, return it instead of looking for
	// an earlier class
	if(element.classList.contains(className)){
		return element;
	}
	
	var parent = element.parentElement; 
	
	while(parent != null){
		if (parent.classList.contains(className)) {
			return parent;
		}
		parent = parent.parentElement;
	}
	
	return null;
}

function getSiblingByClassName(element, className) {
	if (element == null){
		return null;
	}
	
	var sibling = element.nextSibling;
	
	while(sibling){
		if(sibling.nodeType === 1 && sibling != element){
			if (sibling.classList.contains(className)){
				return sibling;
			}
		}
		
		sibling = sibling.nextSibling;
	}
	
	return null;
}

function openTab(tabClass) {
        var x = document.getElementsByClassName("vuln-tab");
        var tabButtons = document.getElementsByClassName("vuln-tab-button");
        for (i = 0; i < x.length; i++) {
            if (x[i].classList.contains(tabClass)){
                x[i].style.display = "block";
                tabButtons[i].style.backgroundColor = "#ffffff";
            }
            else {
                x[i].style.display = "none";
                tabButtons[i].style.backgroundColor = "#f0f0f0";
            }
        }
    }

function formatDate(dateString) {
	var timeZone = "T00:00:00.000-08:00";
	var date = new Date(dateString + timeZone);
	var today = new Date();
	
	return date.toDateString();
}