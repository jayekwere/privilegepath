import { z } from "zod";
import { graphSchema } from "../src/graph.js";

console.log(JSON.stringify(z.toJSONSchema(graphSchema, { unrepresentable: "any" }), null, 2));
