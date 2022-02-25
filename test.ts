async function handle(request: Request): Promise<Response> {
    console.log(request.url);
    let json = JSON.parse(JSON.stringify(request));
    let header = {};
    for (let [key, value] of request.headers.entries())
        header[key] = value;
    json['headers'] = header;
    return new Response(JSON.stringify(json));
}

export default {
    fetch(request: Request) {
        return handle(request);
    }
}