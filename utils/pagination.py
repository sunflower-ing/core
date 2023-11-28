from rest_framework import pagination
from rest_framework.response import Response


class CustomPageNumberPagination(pagination.PageNumberPagination):
    def get_paginated_response(self, data):
        return Response(
            {
                "links": {
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                },
                "count": self.page.paginator.count,
                "total_pages": self.page.paginator.num_pages,
                "current_page": self.page.number,
                "results": data,
            }
        )

    def paginate_queryset(self, queryset, request, view):
        if (
            request.query_params.get("page")
            and request.query_params.get("page") == "all"
        ):
            request.query_params._mutable = True
            request.query_params.pop("page")
            self.page_size = queryset.count()
        return super().paginate_queryset(queryset, request, view)

    def get_paginated_response_schema(self, schema):
        return {
            "type": "object",
            "properties": {
                "count": {
                    "type": "integer",
                    "example": 123,
                },
                "links": {
                    "type": "object",
                    "properties": {
                        "next": {
                            "type": "string",
                            "nullable": True,
                            "format": "uri",
                            "example": "http://api.example.org/view/?page=4",
                        },
                        "previous": {
                            "type": "string",
                            "nullable": True,
                            "format": "uri",
                            "example": "http://api.example.org/view/?page=2",
                        },
                    },
                },
                "total_pages": {
                    "type": "integer",
                    "example": 5,
                },
                "current_page": {
                    "type": "integer",
                    "example": 3,
                },
                "results": schema,
            },
        }
