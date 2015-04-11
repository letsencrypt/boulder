package main

const monitorHTML = `<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="utf-8">
		<title>boulder stats</title>
		<script src="https://code.jquery.com/jquery-2.1.3.min.js"></script>
		<script src="http://code.highcharts.com/highcharts.js"></script>
	</head>
	<body>
		<h1>stats for nerds</h1>
		total calls since monitor started: <span id="calls">0</span><br>
		avg call time: <span id="avgcall">0ms</span> (cumulative)<br>
		current cps: <span id="cps">0</span><br>
		<div id="container" style="min-width: 310px; height: 800px; margin: 0 auto"></div>
		<script>
			function flattenJSONobjs(objs, reduce) {
				flattend = []
				for (var i = 0; i < objs.length; i++) {
					flattend.push([Date.parse(objs[i].At), objs[i].Result/reduce])
				}
				return flattend
			}

			$("#container").highcharts({
				plotOptions: {
					series: {
						states: {
							hover: {
								enabled: false
							}
						}
					}
				},
				tooltip: {
					enabled: false
				},
				credits: {
					enabled: false
				},
				colors: ["rgba(255, 102, 102, 0.75)", "rgba(102, 255, 102, 0.75)", "rgba(255, 102, 255, 0.75)", "rgba(102, 102, 255, 0.75)", "rgba(178, 255, 102, 0.75)", "rgba(255, 178, 102, 0.75)"],
				chart: {
					// type: "scatter",
					events: {
						load: function () {
							// set up the updating of the chart each second
							var chart = this;
							var series = this.series;

							setInterval(function () {
								$.get("http://localhost:8080/stats", function(data) {
									// for each key in data
									for (var key in data.RpcTimings) {
										var editSeries = null;
										for (var i = 0; i < series.length; i++) {
											if (series[i].name == key) {
												editSeries = series[i];
											}
										}
										var dataPoints = flattenJSONobjs(data.RpcTimings[key], 1000000);

										if (editSeries == null) {
											// add series for key
											editSeries = chart.addSeries({type: "scatter", name: key, marker: {symbol: "circle", radius: 2}, yAxis: 0}, false);
										}

										editSeries.setData(dataPoints, false);
									}

									// add / update cps+avg line
									console.log(data);
									var cpsSeries = null;
									var avgSeries = null;
									for (var i = 0; i < series.length; i++) {
										if (series[i].name == "CPS") {
											cpsSeries = series[i];
										} else if (series[i].name == "RPC Call time avg") {
											avgSeries = series[i];
										}
									}
									if (cpsSeries == null) {
										cpsSeries = chart.addSeries({type: "spline", name: "CPS", marker: {enabled: false}, yAxis: 1}, false);
									}
									if (avgSeries == null) {
										avgSeries = chart.addSeries({type: "spline", name: "RPC Call time avg", marker: {enabled: false}, yAxis: 0}, false);
									}
									var cpsDatapoints = flattenJSONobjs(data.CPS, 1);
									var avgDatapoints = flattenJSONobjs(data.AvgCallTook, 1000000);
									cpsSeries.setData(cpsDatapoints, false);
									avgSeries.setData(avgDatapoints, false);

									// redraw chart
									chart.redraw();

									// update text stuff
									$("#calls").text(data.TotalCalls);
									$("#avgcall").text((data.AvgCallTook[data.AvgCallTook.length-1].Result/1000000).toFixed(3)+"ms");
									$("#cps").text(data.CPS[data.CPS.length-1].Result);
								}, "json");
						   }, 5000);
						}
					}
				},
				title: {
					text: ""
				},
				xAxis: {
					type: "datetime",
					title: {
						text: "date"
					},
					gridLineWidth: 0
				},
				yAxis: [{
					labels: {
		                format: '{value}ms'
		            },
					title: {
						text: "RPC call time (ms)"
					},
					min: 0,
					gridLineWidth: 0
				},{
					labels: {
		                format: '{value}'
		            },
					title: {
						text: "CPS"
					},
					min: 0,
					gridLineWidth: 0,
					opposite: true,
					allowDecimals: false
				}],
				series: []
			})
		</script>
	</body>
</html>`
