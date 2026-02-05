const body = document.body;
body.style.cssText="background:#0b0e14;color:white;font-family:sans-serif;padding:30px;";

const app=document.createElement("div");
app.style.maxWidth="1200px";
app.style.margin="auto";
body.appendChild(app);

app.innerHTML=`
<h2>🛡️ Log Guard Engine</h2>

<textarea id="logInput"
style="width:100%;height:160px;background:#010409;color:#7ee787;"></textarea>

<br><br>
<input type="file" id="fileInput">
Threshold <input id="threshold" type="number" value="10">
<button id="scan">SCAN</button>

<!-- CYBER MAP -->
<div id="cyberMap"
style="height:350px;margin-top:25px;border:1px solid #00ff9c44;
box-shadow:0 0 20px #00ff9c33;"></div>

<div id="charts"
style="display:grid;grid-template-columns:1fr 1fr;
gap:20px;margin-top:25px;">
<div style="height:280px"><canvas id="attack"></canvas></div>
<div style="height:280px"><canvas id="risk"></canvas></div>
</div>
`;

let attackChart,riskChart,map,markers=[];

/* ---------------- CYBER MAP INIT ---------------- */

map = L.map('cyberMap',{
 zoomControl:false,
 attributionControl:false
}).setView([20,0],2);

L.tileLayer(
'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
).addTo(map);


/* ----------- Fake Geo Lookup (DEMO PURPOSE) ----------- */
/* Şimdilik IP → random location (sonra gerçek API bağlarız) */

function fakeGeo(ip){
 return [
   Math.random()*140-70,
   Math.random()*360-180
 ];
}


/* ---------------- SCAN BUTTON ---------------- */

document.getElementById("scan").onclick=async()=>{

 let logs=document.getElementById("logInput").value;
 const file=document.getElementById("fileInput").files[0];
 const threshold=document.getElementById("threshold").value;

 if(file) logs=await file.text();

 const res=await fetch("http://127.0.0.1:5000/analyze",{
  method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({
   logs:logs,
   threshold:parseInt(threshold)
  })
 });

 const data=await res.json();

 /* -------- Attack Chart -------- */

 const count={};
 data.incidents.forEach(i=>count[i.type]=(count[i.type]||0)+1);

 if(attackChart)attackChart.destroy();

 attackChart=new Chart(attack,{
  type:"doughnut",
  data:{
    labels:Object.keys(count),
    datasets:[{data:Object.values(count)}]
  },
  options:{maintainAspectRatio:false}
 });


 /* -------- Risk Chart -------- */

 const ips=Object.keys(data.risk_analysis);
 const scores=ips.map(i=>data.risk_analysis[i].score);

 if(riskChart)riskChart.destroy();

 riskChart=new Chart(risk,{
  type:"bar",
  data:{
    labels:ips,
    datasets:[{data:scores,label:"Risk"}]
  },
  options:{maintainAspectRatio:false}
 });


 /* -------- CYBER MAP MARKERS -------- */

 markers.forEach(m=>map.removeLayer(m));
 markers=[];

 ips.forEach(ip=>{
   const [lat,lng]=fakeGeo(ip);

   const marker=L.circleMarker([lat,lng],{
     radius:7,
     color:"#00ff9c",
     fillColor:"#00ff9c",
     fillOpacity:0.9
   }).addTo(map);

   markers.push(marker);
 });

};
