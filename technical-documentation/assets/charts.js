/* TRAE 自动签到技能 · 技术文档图表 */
(function () {
  function initTestChart() {
    var el = document.getElementById("chart-tests");
    if (!el || typeof echarts === "undefined") return;
    var chart = echarts.init(el);
    var modules = [
      { name: "token_refresh", count: 18 },
      { name: "checkin", count: 13 },
      { name: "credentials", count: 8 },
      { name: "crypto", count: 7 },
      { name: "retry", count: 7 },
      { name: "ecdsa", count: 6 }
    ];
    chart.setOption({
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        formatter: function (params) {
          var p = params[0];
          return p.name + "<br/>单元测试：<b>" + p.value + "</b> 项";
        }
      },
      grid: { left: 40, right: 20, top: 24, bottom: 36 },
      xAxis: {
        type: "category",
        data: modules.map(function (m) { return m.name; }),
        axisLabel: { color: "#5d6b85", fontFamily: "JetBrainsMono, monospace", fontSize: 11 },
        axisLine: { lineStyle: { color: "#dde5f1" } },
        axisTick: { show: false }
      },
      yAxis: {
        type: "value",
        minInterval: 1,
        axisLabel: { color: "#5d6b85" },
        splitLine: { lineStyle: { color: "#eef2f9" } }
      },
      series: [{
        type: "bar",
        data: modules.map(function (m) {
          return {
            value: m.count,
            itemStyle: {
              color: m.count >= 10 ? "#2456d6" : "#0d9488",
              borderRadius: [4, 4, 0, 0]
            }
          };
        }),
        barWidth: 42,
        label: {
          show: true,
          position: "top",
          color: "#182136",
          fontWeight: 700,
          fontFamily: "JetBrainsMono, monospace"
        }
      }]
    });
    window.addEventListener("resize", function () { chart.resize(); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initTestChart);
  } else {
    initTestChart();
  }
})();
