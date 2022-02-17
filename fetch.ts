async function handle(request: Request): Promise<Response> {
    let url = new URL(request.url);
    let requestUrl = url.pathname + url.search;
    requestUrl = requestUrl.replace(/^\/*(https?:)(\/*)/, '$1//');
    return fetch(requestUrl, request);
}

export default {
    fetch(request: Request) {
        return handle(request);
    }
}