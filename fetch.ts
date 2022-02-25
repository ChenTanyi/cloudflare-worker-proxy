async function handleFetch(request: Request): Promise<Response> {
    let url = new URL(request.url);
    let requestUrl = url.pathname + url.search;
    requestUrl = requestUrl.replace(/^\/*(https?:)(\/*)/, '$1//');
    return fetch(requestUrl, request);
}

async function handle(request: Request): Promise<Response> {
    console.log(request.url);
    let url = new URL(request.url);
    if (url.pathname.startsWith('/http:/') || url.pathname.startsWith('/https:/')) {
        return handleFetch(request);
    } else {
        return new Response(request.headers.get('x-real-ip'));
    }
}

export default {
    fetch(request: Request) {
        return handle(request);
    }
}