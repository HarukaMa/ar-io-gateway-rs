CREATE TABLE public.graphql_index_state (
    singleton boolean PRIMARY KEY CHECK(singleton),
    ready boolean NOT NULL DEFAULT false
);
INSERT INTO public.graphql_index_state(singleton,ready) VALUES(true,false);
