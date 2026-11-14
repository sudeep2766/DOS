import http from 'k6/http';
export const options = { vus: 50, duration: '60s' };
export default function () {
  http.get(`http://SERVER_IP:8000/feed/${Math.ceil(Math.random()*10000)}`);
}
