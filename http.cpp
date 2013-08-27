#include "http.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <system_error>
#include <algorithm>

using namespace cocaine::docker;

std::vector<std::string>
http_headers_t::headers(const std::string& key) const {
    std::vector<std::string> result;

    for (auto it = m_headers.begin(); it != m_headers.end(); ++it) {
        if (boost::iequals(it->first, key)) {
            result.push_back(it->second);
        }
    }

    return result;
}

boost::optional<std::string>
http_headers_t::header(const std::string& key) const {
    for (auto it = m_headers.begin(); it != m_headers.end(); ++it) {
        if (boost::iequals(it->first, key)) {
            return boost::optional<std::string>(it->second);
        }
    }

    return boost::optional<std::string>();
}

void
http_headers_t::add_header(const std::string& key,
                           const std::string& value)
{
    m_headers.emplace_back(key, value);
}

void
http_headers_t::reset_header(const std::string& key,
                             const std::vector<std::string>& values)
{
    headers_vector_t new_headers;
    new_headers.reserve(m_headers.size() + values.size());

    for (auto header = m_headers.begin(); header != m_headers.end(); ++header) {
        if (!boost::iequals(header->first, key)) {
            new_headers.push_back(*header);
        }
    }

    for (auto value = values.begin(); value != values.end(); ++value) {
        new_headers.emplace_back(key, *value);
    }

    m_headers.swap(new_headers);
}

void
http_headers_t::reset_header(const std::string& key,
                             const std::string& value)
{
    headers_vector_t new_headers;
    new_headers.reserve(m_headers.size() + 1);

    for (auto header = m_headers.begin(); header != m_headers.end(); ++header) {
        if (!boost::iequals(header->first, key)) {
            new_headers.push_back(*header);
        }
    }

    m_headers.swap(new_headers);

    add_header(key, value);
}



base_http_client_t::base_http_client_t(int fd) :
    m_socket(fd),
    m_curl(curl_easy_init())
{
    if (!m_curl) {
        throw std::runtime_error("Unable to initialize libcurl.");
    }

    curl_easy_setopt(m_curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(m_curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);

    curl_easy_setopt(m_curl, CURLOPT_OPENSOCKETFUNCTION, &base_http_client_t::open_callback);
    curl_easy_setopt(m_curl, CURLOPT_OPENSOCKETDATA, this);
    curl_easy_setopt(m_curl, CURLOPT_SOCKOPTFUNCTION, &base_http_client_t::sockopt_callback);
    curl_easy_setopt(m_curl, CURLOPT_CLOSESOCKETFUNCTION, &base_http_client_t::close_callback);
    curl_easy_setopt(m_curl, CURLOPT_CLOSESOCKETDATA, this);
    curl_easy_setopt(m_curl, CURLOPT_HEADERFUNCTION, &base_http_client_t::header_callback);
    curl_easy_setopt(m_curl, CURLOPT_HEADERDATA, this);
    curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, &base_http_client_t::write_callback);
    curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, this);
}

base_http_client_t::~base_http_client_t() {
    destroy();
}

void
base_http_client_t::destroy() {
    curl_easy_cleanup(m_curl);
}

const std::string&
base_http_client_t::body() const {
    return m_body;
}

std::string&
base_http_client_t::body() {
    return m_body;
}

const http_headers_t&
base_http_client_t::headers() const {
    return m_headers;
}

http_headers_t&
base_http_client_t::headers() {
    return m_headers;
}

int
base_http_client_t::request(const http_request_t& request) {
    http_request_t req = request;

    curl_easy_setopt(m_curl, CURLOPT_URL, req.uri().c_str());

    if (req.http_version() == "1.0") {
        curl_easy_setopt(m_curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
    } else if (req.http_version() == "1.1") {
        curl_easy_setopt(m_curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    }

    if (boost::iequals(req.method(), "POST")) {
        curl_easy_setopt(m_curl, CURLOPT_POST, 1L);
        curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, req.body().data());
        curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE, req.body().size());
    }

    req.headers().reset_header("Content-Length", boost::lexical_cast<std::string>(req.body().size()));

    std::vector<std::string> headers;
    curl_slist *p_headers = NULL;
    for (size_t i = 0; i < req.headers().data().size(); ++i) {
        headers.push_back(req.headers().data()[i].first + ": " + req.headers().data()[i].second);
        p_headers = curl_slist_append(p_headers, headers.back().c_str());
    }

    CURLcode errc = curl_easy_perform(m_curl);

    curl_slist_free_all(p_headers);

    if (errc != 0) {
        throw std::system_error(errc, std::system_category(), curl_easy_strerror(errc));
    }

    int code = 200;
    curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &code);

    return code;
}

curl_socket_t
base_http_client_t::open_callback(void* user_data,
                                  curlsocktype /* purpose */,
                                  curl_sockaddr * /* address */)
{
    return static_cast<base_http_client_t*>(user_data)->m_socket;
}

int
base_http_client_t::sockopt_callback(void * /* user_data */,
                                     curl_socket_t /* fd */,
                                     curlsocktype /* purpose */)
{
    return CURL_SOCKOPT_ALREADY_CONNECTED;
}

int
base_http_client_t::close_callback(void * /* user_data */,
                                   curl_socket_t /* fd */)
{
    return 0;
}

std::string
strip(const char *begin,
      const char *end)
{
    while (begin < end && isspace(*begin)) {
        ++begin;
    }

    while (begin < end && isspace(*(end - 1))) {
        --end;
    }

    if (begin < end) {
        return std::string(begin, end - begin);
    } else {
        return std::string();
    }
}

size_t
base_http_client_t::header_callback(const char *header,
                                    size_t size,
                                    size_t nmemb,
                                    void *user_data)
{
    const char *end = header + size * nmemb;
    const char *delim = std::find(header, end, ':');

    if (delim != end) {
        const char *last_char = std::find(delim, end, '\n');

        std::string field = strip(header, delim);
        std::string value = strip(delim + 1, last_char);

        static_cast<base_http_client_t*>(user_data)
            ->m_headers.add_header(std::move(field), std::move(value));
    }

    return size * nmemb;
}

size_t
base_http_client_t::write_callback(const char *body,
                                   size_t size,
                                   size_t nmemb,
                                   void *user_data)
{
    static_cast<base_http_client_t*>(user_data)
        ->m_body += std::string(body, size * nmemb);

    return size * nmemb;
}
