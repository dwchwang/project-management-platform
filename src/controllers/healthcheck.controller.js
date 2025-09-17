import { asyncHandler } from '../utils/async-handler.js';
import { ApiResponse } from '../utils/api-response.js';


export const healthCheck = asyncHandler(async (req, res, next) => {
  res
    .status(200)
    .json(new ApiResponse(200, {message: "Server is running"} ))
})