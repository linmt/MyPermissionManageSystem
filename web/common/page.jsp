<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<script id="paginateTemplate" type="x-tmpl-mustache">
<div class="col-xs-6">
    <div class="dataTables_info" id="dynamic-table_info" role="status" aria-live="polite">
        总共 {{total}} 中的 {{from}} ~ {{to}}
    </div>
</div>
    
<div class="col-xs-6">
    <div class="dataTables_paginate paging_simple_numbers" id="dynamic-table_paginate">
        <ul class="pagination">
            <li class="paginate_button previous {{^firstUrl}}disabled{{/firstUrl}}" aria-controls="dynamic-table" tabindex="0">
                <a href="#" data-target="1" data-url="{{firstUrl}}" class="page-action">首页</a>
            </li>
            <li class="paginate_button {{^beforeUrl}}disabled{{/beforeUrl}}" aria-controls="dynamic-table" tabindex="0">
                <a href="#" data-target="{{beforePageNo}}" data-url="{{beforeUrl}}" class="page-action">前一页</a>
            </li>
            <li class="paginate_button active" aria-controls="dynamic-table" tabindex="0">
                <a href="#" data-id="{{pageNo}}" >第{{pageNo}}页</a>
                <input type="hidden" class="pageNo" value="{{pageNo}}" />
            </li>
            <li class="paginate_button {{^nextUrl}}disabled{{/nextUrl}}" aria-controls="dynamic-table" tabindex="0">
                <a href="#" data-target="{{nextPageNo}}" data-url="{{nextUrl}}" class="page-action">后一页</a>
            </li>
            <li class="paginate_button next {{^lastUrl}}disabled{{/lastUrl}}" aria-controls="dynamic-table" tabindex="0">
                <a href="#" data-target="{{maxPageNo}}" data-url="{{lastUrl}}" class="page-action">尾页</a>
            </li>
        </ul>
    </div>
</div>
</script>

<script type="text/javascript">
    //解析模板
    var paginateTemplate = $("#paginateTemplate").html();
    Mustache.parse(paginateTemplate);

    //请求的链接 行数 当前多少页  每页行数  当前页有多少条结果  这些值要放在哪个元素  回调函数
    function renderPage(url, total, pageNo, pageSize, currentSize, idElement, callback) {
        pageNo=parseInt(pageNo);
        //alert(url+"  "+total+"  "+pageNo+"  "+pageSize+"  "+currentSize);
        //   /sys/user/page.json?deptId=1  3  1  10  3
        //当前最大的页数
        var maxPageNo = Math.ceil(total / pageSize);
        //拼接实际请求的URL
        var paramStartChar = url.indexOf("?") > 0 ? "&" : "?";
        var from = (pageNo - 1) * pageSize + 1;
        var view = {
            from: from > total ? total : from,
            to: (from + currentSize - 1) > total ? total : (from + currentSize - 1),
            total : total,
            pageNo : pageNo,
            maxPageNo : maxPageNo,
            nextPageNo: pageNo >= maxPageNo ? maxPageNo : (pageNo+1),
            beforePageNo : pageNo == 1 ? 1 : (pageNo - 1),
            firstUrl : (pageNo == 1) ? '' : (url + paramStartChar + "pageNo=1&pageSize=" + pageSize),
            beforeUrl: (pageNo == 1) ? '' : (url + paramStartChar + "pageNo=" + (pageNo - 1) + "&pageSize=" + pageSize),
            nextUrl : (pageNo >= maxPageNo) ? '' : (url + paramStartChar + "pageNo=" + (pageNo + 1) + "&pageSize=" + pageSize),
            lastUrl : (pageNo >= maxPageNo) ? '' : (url + paramStartChar + "pageNo=" + maxPageNo + "&pageSize=" + pageSize)
//            firstUrl : (url.indexOf('pageNo=')<0) ? (url + paramStartChar + "pageNo=1&pageSize=" + pageSize) : (url.replace(/pageNo=\d+/g,'pageNo=1').replace(/pageSize=\d+/g,'pageSize='+pageSize)),
//            beforeUrl: (pageNo == 1) ? '' : (url.replace(/pageNo=\d+/g,'pageNo='+(pageNo - 1)).replace(/pageSize=\d+/g,'pageSize='+pageSize)),
//            nextUrl : (pageNo >= maxPageNo) ? '' : ((url.indexOf('pageNo=')<0) ?(url + paramStartChar + "pageNo=" + (pageNo + 1) + "&pageSize=" + pageSize):(url.replace(/pageNo=\d+/g,'pageNo='+(pageNo + 1)).replace(/pageSize=\d+/g,'pageSize='+pageSize))),
//            lastUrl : (pageNo >= maxPageNo) ? '' : ((url.indexOf('pageNo=')<0) ?(url + paramStartChar + "pageNo=" + maxPageNo + "&pageSize=" + pageSize):(url.replace(/pageNo=\d+/g,'pageNo='+maxPageNo).replace(/pageSize=\d+/g,'pageSize='+pageSize)))
        };
        $("#" + idElement).html(Mustache.render(paginateTemplate, view));
//        alert(view.pageNo+123);
        //  /sys/user/page.json?deptId=2&pageNo=11&pageSize=10
        $(".page-action").click(function(e) {
            e.preventDefault();
            //  .pageNo前有空格
            $("#"+idElement+" .pageNo").val($(this).attr("data-target"));
//            var testPageNo=$(this).attr("data-target");
//            var testPageNo=$("#userPage .pageNo").val($(this).attr("data-target"));
            var targetUrl  = $(this).attr("data-url");
            if(targetUrl != '') {
                $.ajax({
                    url : targetUrl,
                    success: function (result) {
                        if (callback) {
                            callback(result, url);
                        }
                    }
                })
            }
        })
    }
</script>
