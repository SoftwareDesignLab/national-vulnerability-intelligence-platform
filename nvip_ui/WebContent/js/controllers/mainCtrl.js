app.controller('MainController', [ '$scope', '$http', '$routeParams', '$cookieStore', function($scope, $http, $routeParams, $cookieStore) {
     
    $http.defaults.headers.post["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
    
    $scope.init = function () {
		$scope.toggleLoadingScreen(true, "nvip-daily-graph-box");
    	$scope.countGraphs();
    };
    
    /** Controller Functions **/
    $scope.countGraphs = function () {
    	
    	$http({
            url : 'mainServlet',
            method : "GET",  
            params : {countGraphs: "all"}       
        }).then(function(response) {
            $scope.countGraphs = {};
            
            angular.forEach(response.data.map.mainPageCounts.map, function(value, key) {
            	$scope.countGraphs[key] = value;
            });
            
			$scope.loadGraphs();            
			$scope.toggleLoadingScreen(false, "nvip-daily-graph-box");
        }, function(response) {
        	if (response.status == 401){
				alert(response.data);
            	window.location.assign(window.location.href+"login");
            }
           
            console.log("Failure -> " + response.data);
            $scope.countGraphs = response.data.map;
        });
	};
    
	$scope.toggleLoadingScreen = function(loading, className){
		if(className == "nvip-daily-graph-box"){
    		var graphBox = document.getElementsByClassName("nvip-daily-graph-box")[0];
			var loadingScreen = graphBox.getElementsByClassName("nvip-loading-screen")[0];
			var circleGraphs = graphBox.getElementsByClassName("nvip-circle-graph");
    		if(loading){
    			loadingScreen.style.display = 'block';
				angular.forEach(circleGraphs, function(circleGraph, index) {
					circleGraph.style.display = 'none';
				});
    		} 
    		else {
    			loadingScreen.style.display = 'none';
				angular.forEach(circleGraphs, function(circleGraph, index) {
					circleGraph.style.display = 'block';
				});
    		}
    	}
    		
    }

	$scope.loadGraphs = function() {
	
		google.charts.load('47', {'packages':['bar', 'corechart', 'line']});
    	google.charts.setOnLoadCallback(setGraphs);
	}
	
	function setGraphs() {
		
			if (!(window.location.href).includes('/login')) {
				return
			}
		
		
			var newDates = [];
			var dates = $scope.countGraphs.run_date_times.split(";");
			
			//1rst Graph Init
		    var data1 = new google.visualization.DataTable();
	
			data1.addColumn("string", "");
			data1.addColumn("number", "# of CVEs Added or Updated");
			
			var addedCount = $scope.countGraphs.CvesAdded.split(";");
			var updatedCount = $scope.countGraphs.CvesUpdated.split(";");
				
			//2nd Graph Init
			var data2 = new google.visualization.DataTable();
		  
			data2.addColumn("string", ""); //run date time
			data2.addColumn("number", "CVEs Not In NVD");
				
	        var dates = $scope.countGraphs.run_date_times.split(";");		  
	        var nNVD = $scope.countGraphs.not_in_nvd_count.split(";");

			//3rd Graph Init
			var data3 = new google.visualization.DataTable();
		  
			data3.addColumn("string", ""); //run date time
			data3.addColumn("number", "Avg. Time Gap From NVD");
		  
	        var avgNVD = $scope.countGraphs.avgTimeGapNvd.split(";");
	
			var prevDate = "";
				
			for (var i = dates.length - 1; i > -1; i--) {
				var mysqlDate = new Date(dates[i]);
				var date = ((mysqlDate.getMonth()+1)+'/'+mysqlDate.getDate());
				newDates[i] = date;  
				
				if (prevDate !== newDates[i]) {
					
					if (addedCount[i] != null && updatedCount[i] != null) {
						if (i % 2 == 0) {
							data1.addRow([newDates[i], (parseInt(addedCount[i]) + parseInt(updatedCount[i]))]);
						} else {
							data1.addRow(["", (parseInt(addedCount[i]) + parseInt(updatedCount[i]))]);
						}
					}
					
					if (nNVD[i] != null) {
						if (i % 2 == 0) {
					  		data2.addRow([newDates[i], parseInt(nNVD[i])]);
						} else { 
							data2.addRow(["", parseInt(nNVD[i])]);
						}
					}
						
					if (avgNVD[i] != null) {
						if (i % 2 == 0) {
					  		data3.addRow([newDates[i], parseInt(avgNVD[i])]);
						} else {
							data3.addRow(["", parseInt(avgNVD[i])]);
						}
					}
					
					prevDate = newDates[i];
							
				}
				
			}
			
			//1rst graph style
		     
			var baseWidth = document.getElementById("graph").clientWidth;
			var generalWidth = baseWidth - (.1*(baseWidth));

			var options1 = {
		        legend: { position: 'none' },
		        bar: { groupWidth: "60%" },
				height: 167,
				width: generalWidth,
				backgroundColor: {
					fill: '#F5F5F5',	
				},
				chartArea: {
					left: 23,
					top: 10,
					width: '95%',
					height: '77%',
					backgroundColor: '#F5F5F5',
				},
				vAxis: {
					gridlines: {
						color: 'black'
					},
					baselineColor:'black',
					textStyle: {
						color: 'black'
					}
				},
				hAxis: {
					minTextSpacing: 30,
					baselineColor: 'black',
					textStyle: {
						color: 'black'
					}
				},
				colors: ['#d9895d'],
				enableInteractivity: false,
			};
			
			//2nd graph style
		    var options2 = {
					legend: { position: 'none' },
					bar: { groupWidth: "60%" },
					height: 167,
					width: generalWidth,
					backgroundColor: {
						fill: '#F5F5F5',	
					},
					chartArea: {
						left: 23,
						top: 10,
						width: '95%',
						height: '77%',
						backgroundColor: '#F5F5F5',
					},
					vAxis: {
						gridlines: {
							color: 'black'
						},
						baselineColor:'black',
						textStyle: {
							color: 'black'
						}
					},
					hAxis: {
						minTextSpacing: 30,
						textStyle: {
							color: 'black'
						},
						baselineColor: 'black',
					},
					colors: ['#d9895d'],
					enableInteractivity: false,
			  };
	
			//3rd graph style
		    var options3 = {
					legend: { position: 'none' },
					bar: { groupWidth: "60%" },
					height: 167,
					width: generalWidth,
					backgroundColor: {
						fill: '#F5F5F5',	
					},
					chartArea: {
						left: 23,
						top: 10,
						width: '95%',
						height: '77%',
						backgroundColor: '#F5F5F5',
					},
					vAxis: {
						gridlines: {
							color: 'black'
						},
						baselineColor:'black',
						textStyle: {
							color: 'black'
						}
					},
					hAxis: {
						minTextSpacing: 30,
						textStyle: {
							color: 'black'
						},
						baselineColor: 'black',
					},
				  colors: ['#d9895d'],
				  enableInteractivity: false,
			  };
		      
			var chart1 = new google.visualization.ColumnChart(document.getElementById('chart_values1'));
	     
			var chart2 = new google.visualization.ColumnChart(document.getElementById('chart_values2'));
	
			var chart3 = new google.visualization.ColumnChart(document.getElementById('chart_values3'));
	
			chart1.draw(data1, options1);
	
			chart2.draw(data2, options2);
	
			chart3.draw(data3, options3);
	
			window.onresize = setGraphs;
	 
		}
	
} ]);