// small helper JS used across templates

// show messages in a nice way (simple)
function showMessage(msg) {
  alert(msg);
}

// simple function to post JSON and return json
async function postJSON(url, data){
  const res = await fetch(url, {
    method: "POST",
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(data)
  });
  const json = await res.json();
  json.status = res.status;
  return json;
}
