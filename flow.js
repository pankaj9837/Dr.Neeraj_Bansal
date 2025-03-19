/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import axios from "axios";

// this object is generated from Flow Builder under "..." > Endpoint > Snippets > Responses
const SCREEN_RESPONSES = {
    APPOINTMENT: {
      screen: "APPOINTMENT",
      data: {
        department: [
          {
            id: "shopping",
            title: "Shopping & Groceries",
          },
          {
            id: "clothing",
            title: "Clothing & Apparel",
          },
          {
            id: "home",
            title: "Home Goods & Decor",
          },
          {
            id: "electronics",
            title: "Electronics & Appliances",
          },
          {
            id: "beauty",
            title: "Beauty & Personal Care",
          },
        ],
        location: [
          {
            id: "1",
            title: "King\u2019s Cross, London",
          },
          {
            id: "2",
            title: "Oxford Street, London",
          },
          {
            id: "3",
            title: "Covent Garden, London",
          },
          {
            id: "4",
            title: "Piccadilly Circus, London",
          },
        ],
        is_location_enabled: true,
        // date: [
        //   {
        //     id: "2024-01-01",
        //     title: "Mon Jan 01 2024",
        //   },
        //   {
        //     id: "2024-01-02",
        //     title: "Tue Jan 02 2024",
        //   },
        //   {
        //     id: "2024-01-03",
        //     title: "Wed Jan 03 2024",
        //   },
        // ],
        is_date_enabled: true,
        time: [
          {
            id: "10:00",
            title: "10:00",
          },
          {
            id: "11:21",
            title: "11:21",
            enabled: false,
          },
          {
            id: "11:31",
            title: "11:31",
          },
          {
            id: "12:11",
            title: "12:11",
            enabled: false,
          },
          {
            id: "12:30",
            title: "12:11",
          },
        ],
        is_time_enabled: true,
        img:"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"
      },
    },
    DETAILS: {
      screen: "DETAILS",
      data: {
       symptoms:[
          {
            id: "Cold",
            title: "cold",
          },
          {
            id: "Cough",
            title: "Cough",
          },
       ]
      },
    },
    SUMMARY: {
      screen: "SUMMARY",
      data: {
        appointment:
          "Beauty & Personal Care Department at Kings Cross, London\nMon Jan 01 2024 at 11:30.",
        details:
          "Name: John Doe\nEmail: john@example.com\nPhone: 123456789\n\nA free skin care consultation, please",
        department: "beauty",
        location: "1",
        date: "2024-01-01",
        time: "11:30",
        name: "John Doe",
        email: "john@example.com",
        phone: "123456789",
        more_details: "A free skin care consultation, please",
      },
    },
    TERMS: {
      screen: "TERMS",
      data: {},
    },
    SUCCESS: {
      screen: "SUCCESS",
      data: {
        extension_message_response: {
          params: {
            flow_token: "REPLACE_FLOW_TOKEN",
            some_param_name: "PASS_CUSTOM_VALUE",
          },
        },
      },
    },
  };

  
  export const getNextScreen = async (decryptedBody) => {
    const { screen, data, version, action, flow_token } = decryptedBody;

    const getdata=async(search)=>{
        let res=await axios.get(`https://api.duniyatech.com/WhatsApp-cloud-api/fatch_date_and_time/${search}`)
        console.log(res.data)
        return res.data
    }
   

    // handle health check request
    if (action === "ping") {
      return {
        data: {
          status: "active",
        },
      };
    }
  
    // handle error notification
    if (data?.error) {
      console.warn("Received client error:", data);
      return {      
        data: {
          acknowledged: true,
        },
      };
    }
  
    // handle initial request when opening the flow and display APPOINTMENT screen
    if (action === "INIT") {
       let resdate= await getdata('date')
      return {
        ...SCREEN_RESPONSES.APPOINTMENT,
        data: {
          ...SCREEN_RESPONSES.APPOINTMENT.data,
          date:resdate,
          // these fields are disabled initially. Each field is enabled when previous fields are selected
          is_date_enabled: true,
          is_time_enabled: false,
        },
      };
    }
  
    if (action === "data_exchange") {
      // handle the request based on the current screen
      switch (screen) {
        // handles when user interacts with APPOINTMENT screen
        case "APPOINTMENT":
          // update the appointment fields based on current user selection

          if(data.trigger === "Date_selected"){
            const restime= await getdata(data.Date_of_appointment)
            return {
                ...SCREEN_RESPONSES.APPOINTMENT,
    
                data: {
                  // copy initial screen data then override specific fields
                  ...SCREEN_RESPONSES.APPOINTMENT.data,
                  time:restime,
                  is_time_enabled: true
                },
              };
          }

          const appointment = `${data.Date_of_appointment_0} at ${data.Time_Slot_1}`;
          
          const details = `Name: ${data.Patient_Name_2}
Guardian: ${data.Guardian_Name}
DOB: ${data.Date_Of_Birth}
Age: ${data.Age_3}
Email: ${data.Email_4}
Symptoms: ${data.Other_Symptoms_5}
City: ${data.City}
Address: ${data.Address}`;
          return {
            ...SCREEN_RESPONSES.DETAILS,

            data: {
              // copy initial screen data then override specific fields
              ...SCREEN_RESPONSES.DETAILS.data,
              appointment,
              details,
              ...data
            },
          };
  
//         // handles when user completes DETAILS screen
//         case "DETAILS":
//           // the client payload contains selected ids from dropdown lists, we need to map them to names to display to user
//           const departmentName =
//             SCREEN_RESPONSES.APPOINTMENT.data.department.find(
//               (dept) => dept.id === data.department
//             ).title;
//           const locationName = SCREEN_RESPONSES.APPOINTMENT.data.location.find(
//             (loc) => loc.id === data.location
//           ).title;
//           const dateName = SCREEN_RESPONSES.APPOINTMENT.data.date.find(
//             (date) => date.id === data.date
//           ).title;
  
//           const appointment = `${departmentName} at ${locationName}
//   ${dateName} at ${data.time}`;
  
//           const details = `Name: ${data.name}
//   Email: ${data.email}
//   Phone: ${data.phone}
//   "${data.more_details}"`;
  
//           return {
//             ...SCREEN_RESPONSES.SUMMARY,
//             data: {
//               appointment,
//               details,
//               // return the same fields sent from client back to submit in the next step
//               ...data,
//             },
//           };
  
        // handles when user completes SUMMARY screen
        case "SUMMARY":
          // TODO: save appointment to your database
          // send success response to complete and close the flow
          return {
            ...SCREEN_RESPONSES.SUCCESS,
            data: {
              extension_message_response: {
                params: {
                  flow_token,
                },
              },
            },
          };
  
        default:
          break;
      }
    }
  
    console.error("Unhandled request body:", decryptedBody);
    throw new Error(
      "Unhandled endpoint request. Make sure you handle the request action & screen logged above."
    );
  };
